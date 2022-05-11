open Devkit
open ExtLib

let _opt_str x = Option.default "NONE" x

type authentication_method =
  | Raw
  | Basic
  | Bearer
  | Digest

type indirect_string =
  | Immediate of string
  | Env of string
  | File of string
  | Pass of string

type form_data = (string * indirect_string option) list

type body =
  | Raw of indirect_string
  | Form of form_data
  | JSON of indirect_string

type config = {
  authentication : (authentication_method * indirect_string) option;
  base_uri : string;
  body : body option;
  content_type : string option;
  dry_run : bool;
  headers : form_data;
  pass : string;
  path : indirect_string list;
  query : form_data;
  raw_form : bool;
  raw_path : bool;
  raw_query : bool;
  verb : Web.http_action;
}

type ('a, 'c) e =
  | Map : { map1 : 'a -> 'b Lwt.t; map2 : 'b -> 'c Lwt.t; } -> ('a, 'c) e

let siesta params =
  let {
    authentication;
    base_uri;
    body;
    content_type;
    dry_run;
    headers;
    pass;
    path;
    query;
    raw_form;
    raw_path;
    raw_query;
    verb;
  } = params in
  Lwt_main.run @@
  let add_type type_ map value = String.concat " " [ type_; map value; ] in
  let basic = add_type "Basic" Base64.encode_string in
  let bearer = add_type "Bearer" Fun.id in
  let return_env_lines (Map { map1; map2; }) name =
    let lines = Lwt_stream.of_list (try [ Sys.getenv name; ] with Not_found -> []) in
    let%lwt lines = map1 lines in
    map2 lines
  in
  let return_file map0 (Map { map1; map2; }) name =
    Lwt_io.with_file ~mode:Input name @@ fun io ->
    let%lwt lines = map0 io in
    let%lwt lines = map1 lines in
    map2 lines
  in
  let return_file_lines map name = return_file (Lwt.wrap1 Lwt_io.read_lines) map name in
  let return_pass map0 (Map { map1; map2; }) name =
    let%lwt lines = map0 ("", [| pass; name; |]) in
    let%lwt lines = map1 lines in
    map2 lines
  in
  let return_pass_lines map name = return_pass (Lwt.wrap1 Lwt_process.pread_lines) map name in
  let%lwt authentication =
    match authentication with
    | None -> Lwt.return_none
    | Some (authentication, x) ->
    let indirect = function
      | (Raw : authentication_method) -> Map { map1 = Lwt_stream.get; map2 = Lwt.return; }
      | Basic -> Map { map1 = Lwt_stream.to_list; map2 = (fun x -> Lwt.return_some (basic (String.concat ":" x))); }
      | Bearer -> Map { map1 = Lwt_stream.next; map2 = Lwt.return_some $ basic; }
      | Digest -> Exn.fail "FIXME auth digest is not implemented"
    in
    match x with
    | Immediate x ->
      begin match authentication with
      | Raw -> Lwt.return_some x
      | Basic -> Lwt.return_some (basic x)
      | Bearer -> Lwt.return_some (bearer x)
      | Digest -> Exn.fail "FIXME auth digest is not implemented"
      end
    | Env x -> return_env_lines (indirect authentication) x
    | File x -> return_file_lines (indirect authentication) x
    | Pass x -> return_pass_lines (indirect authentication) x
  in
  let authentication = Option.map ((^) "Authorization: ") authentication in
  let map_header key value = String.concat ": " [ key; value; ] in
  let%lwt headers =
    let indirect key acc =
      Map { map1 = Lwt.return; map2 = (fun x -> Lwt_stream.fold (fun value acc -> map_header key value :: acc) x acc); }
    in
    Lwt_list.fold_left_s begin fun acc (key, value) ->
      match value with
      | None -> Lwt.return ((key ^ ":") :: acc)
      | Some value ->
      match value with
      | Immediate value -> Lwt.return (map_header key value :: acc)
      | Env value -> return_env_lines (indirect key acc) value (* FIXME embedded newlines *)
      | File value -> return_file_lines (indirect key acc) value (* FIXME duplicate headers *)
      | Pass value -> return_pass_lines (indirect key acc) value
    end [] headers
  in
  let headers =
    List.fold_left begin fun acc header ->
      match header with
      | Some header -> header :: acc
      | None -> acc
    end headers [ authentication; ]
  in
  let map_form_data l =
    let indirect key acc =
      Map { map1 = Lwt.return; map2 = (fun x -> Lwt_stream.fold (fun value acc -> (key, Some value) :: acc) x acc); }
    in
    List.rev l |>
    Lwt_list.fold_left_s begin fun acc (key, value) ->
      match value with
      | None -> Lwt.return ((key, None) :: acc)
      | Some value ->
      match value with
      | Immediate value -> Lwt.return ((key, Some value) :: acc)
      | Env value -> return_env_lines (indirect key acc) value
      | File value -> return_file_lines (indirect key acc) value
      | Pass value -> return_pass_lines (indirect key acc) value
    end []
  in
  let%lwt query = map_form_data query in
  let%lwt path =
    let indirect acc =
      Map { map1 = Lwt.return; map2 = (fun x -> Lwt_stream.fold (fun value acc -> value :: acc) x acc); }
    in
    List.rev path |>
    Lwt_list.fold_left_s begin fun acc value ->
      match value with
      | Immediate value -> Lwt.return (value :: acc)
      | Env value -> return_env_lines (indirect acc) value
      | File value -> return_file_lines (indirect acc) value
      | Pass value -> return_pass_lines (indirect acc) value
    end []
  in
  let encode_uri_component = function true -> Fun.id | false -> Web.urlencode in
  let encode_path_component = encode_uri_component raw_path in
  let encode_query_component = encode_uri_component raw_query in
  let encode_form_component = encode_uri_component raw_form in
  let encode_query encode = function
    | key, Some value -> String.concat "=" [ encode key; encode value; ]
    | key, None -> encode key
  in
  let encode_query encode query = Stre.catmap ~sep:"&" (encode_query encode) query in
  let full_uri = String.concat "/" (base_uri :: List.map encode_path_component path) in
  let full_uri =
    match query with
    | _ :: _ -> String.concat "?" [ full_uri; encode_query encode_query_component query; ]
    | [] -> full_uri
  in
  let%lwt body =
    match body with
    | None -> Lwt.return_none
    | Some body ->
    let raw detect_content_type content =
      let%lwt content_type =
        match content_type with
        | Some content_type -> Lwt.return content_type
        | None -> detect_content_type ()
      in
      Lwt.return_some (`Raw (content_type, content))
    in
    let json_mime_type = "application/json" in
    let detect_content_type name () =
      Lwt_process.pread_line ("", [| "file"; "--brief"; "--dereference"; "--mime-type"; name; |])
    in
    let indirect ?(force_default_content_type=false) default_content_type = function
      | Immediate value -> Lwt.return (const (Lwt.return default_content_type), value)
      | Env value ->
        let%lwt value =
          match Sys.getenv value with
          | value -> Lwt.return value
          | exception Not_found ->
            let%lwt () = Lwt_io.eprintlf "WARN: environment variable `%s' is not set, using empty value" value in
            Lwt.return ""
        in
        Lwt.return (const (Lwt.return default_content_type), value)
      | File value' ->
        let%lwt value = Lwt_io.with_file ~mode:Input value' Lwt_io.read in
        let detect_content_type =
          match force_default_content_type with
          | false -> detect_content_type
          | true ->
          let detect_content_type name () =
            let%lwt content_type = detect_content_type name () in
            let%lwt () =
              match String.equal content_type default_content_type with
              | true -> Lwt.return_unit
              | false ->
                Lwt_io.eprintlf "WARN: detected content type of `%s' is %s, using %s instead" value' content_type json_mime_type
            in
            Lwt.return default_content_type
          in
          detect_content_type
        in
        Lwt.return (detect_content_type value, value)
      | Pass value ->
        let%lwt value = return_pass Lwt_process.pread (Map { map1 = Lwt.return; map2 = Lwt.return; }) value in
        Lwt.return (const (Lwt.return default_content_type), value)
    in
    match body with
    | Raw x ->
      let%lwt (detect_content_type, x) = indirect "application/octet-stream" x in
      raw detect_content_type x
    | Form x ->
      let%lwt x = map_form_data x in
      let content_type = const (Lwt.return "application/x-www-form-urlencoded") in
      raw content_type (encode_query encode_form_component x)
    | JSON x' ->
      let%lwt (detect_content_type, x) = indirect ~force_default_content_type:true json_mime_type x' in
      raw detect_content_type x
  in
  match dry_run with
  | true ->
    (* TODO also print if verbose *)
    let%lwt () = Lwt_io.eprintlf "%s %s" (Web.string_of_http_action verb) full_uri in
    Lwt.return_unit
  | false ->
  match%lwt Web.http_request_lwt' ~headers ?body verb full_uri with
  | `Ok (_code, s) ->
    (* TODO print HTTP code if verbose *)
    Lwt_io.printl s
  | `Error code -> Lwt_io.eprintlf "ERROR: curl error (%d) %s" (Curl.int_of_curlCode code) (Curl.strerror code)

open Cmdliner

let indirect_string =
  let parse = Arg.(conv_parser string) in
  let parse x =
    match parse x with
    | Error _ as error -> error
    | Ok x ->
    let len = String.length x in
    match len = 0 with
    | true -> Ok (Immediate x)
    | false ->
    let sub len x = String.sub x 1 (pred len) in
    match String.unsafe_get x 0 with
    | '=' -> Ok (Immediate (sub len x))
    | '$' -> Ok (Env (sub len x))
    | '@' -> Ok (File (sub len x))
    | '!' -> Ok (Pass (sub len x))
    | _ -> Ok (Immediate x)
  in
  let print = Arg.(conv_printer string) in
  let print fmt x =
    match x with
    | Env x -> print fmt ("$" ^ x)
    | File x -> print fmt ("@" ^ x)
    | Pass x -> print fmt ("!" ^ x)
    | Immediate x ->
    let starts_with_special x =
      match String.unsafe_get x 0 with
      | '=' | '@' | '!' -> true
      | _ -> false
    in
    match String.equal x "" || not (starts_with_special x) with
    | true -> print fmt x
    | false -> print fmt ("=" ^ x)
  in
  Arg.conv (parse, print)

let key_and_value =
  let key_and_value = Arg.(pair ~sep:'=' string indirect_string) in
  let parse = Arg.(conv_parser key_and_value) in
  let parse x =
    match String.contains x '=' with
    | false -> Ok (x, None)
    | true ->
    match parse x with
    | Ok (key, value) -> Ok (key, Some value)
    | Error _ as error -> error
  in
  let print = Arg.(conv_printer key_and_value) in
  let print fmt (key, value) =
    match value with
    | Some value -> print fmt (key, value)
    | None -> Format.pp_print_string fmt key
  in
  Arg.conv (parse, print)

let authentication =
  let doc = "Specify the raw authentication." in
  Arg.(value & opt (some indirect_string) None & info ["a"; "auth"] ~docv:"AUTH" ~doc)

let base_uri =
  let doc = "Specify the base URI for the API call." in
  let uri =
    let parse = Arg.(conv_parser string) in
    let parse x =
      match parse x with
      | Ok x -> Ok (if String.ends_with x "/" then String.rchop x else x)
      | Error _ as error -> error
    in
    Arg.conv (parse, Arg.(conv_printer string))
  in
  Arg.(required & pos 0 (some uri) None & info [] ~docv:"BASE_URI" ~doc)

let bearer =
  let doc = "Specify the bearer token for OAuth2 server authentication." in
  Arg.(value & opt (some indirect_string) None & info ["b"; "bearer"] ~docv:"BEARER" ~doc)

let content =
  let doc = "Specify the content for the API call." in
  Arg.(value & opt (some indirect_string) None & info ["c"; "content"] ~docv:"CONTENT" ~doc)

let content_type =
  let doc = "Specify the content type for the API call." in
  Arg.(value & opt (some string) None & info ["t"; "content-type"] ~docv:"CONTENT_TYPE" ~doc)

let data =
  let doc = "Specify the form data for the API call." in
  Arg.(value & opt_all key_and_value [] & info ["d"; "data"] ~docv:"DATA" ~doc)

let digest =
  let doc = "Use digest authentication (TODO)." in
  Arg.(value & flag & info ["D"; "digest"] ~docv:"DIGEST" ~doc)

let dry_run =
  let doc = "Dry run, print the API call that would be made." in
  Arg.(value & flag & info ["n"; "dry-run"] ~docv:"DRY_RUN" ~doc)

let headers =
  let doc = "Specify header for the API call." in
  Arg.(value & opt_all key_and_value [] & info ["h"; "header"] ~docv:"HEADER" ~doc)

let json =
  let doc = "Specify the json data for the API call." in
  Arg.(value & opt (some indirect_string) None & info ["j"; "json"] ~docv:"JSON" ~doc)

let pass =
  let doc = "Specify the password manager program to use." in
  Arg.(value & opt string "pass" & info ["p"; "pass"] ~docv:"PASS" ~doc)

let path =
  let doc = "Specify the HTTP request path for the API call." in
  Arg.(value & pos_right 1 indirect_string [] & info [] ~docv:"API_PATH" ~doc)

let query =
  let doc = "Specify the query for the API call." in
  Arg.(value & opt_all key_and_value [] & info ["q"; "query"] ~docv:"QUERY" ~doc)

let raw_form =
  let doc = "Don't URL-encode form data query components." in
  Arg.(value & flag & info ["F"; "raw-form"] ~docv:"RAW_FORM" ~doc)

let raw_path =
  let doc = "Don't URL-encode path components." in
  Arg.(value & flag & info ["P"; "raw-path"] ~docv:"RAW_PATH" ~doc)

let raw_query =
  let doc = "Don't URL-encode query components." in
  Arg.(value & flag & info ["Q"; "raw-query"] ~docv:"RAW_QUERY" ~doc)

let user =
  let doc = "Specify the user authentication." in
  Arg.(value & opt (some indirect_string) None & info ["u"; "user"] ~docv:"USERAUTH" ~doc)

let verb =
  let doc = "Specify the HTTP request verb for the API call." in
  let verb =
    let parse x =
      match Web.http_action_of_string (String.uppercase_ascii x) with
      | verb -> Ok verb
      | exception (Failure msg) -> Error (`Msg msg)
    in
    let print fmt x =
      Format.pp_print_string fmt (Web.string_of_http_action x)
    in
    Arg.conv (parse, print) ~docv:"VERB"
  in
  Arg.(required & pos 1 (some verb) None & info [] ~docv:"API_VERB" ~doc)

let siesta_t =
  let (let+) x f = Term.(const f $ x) in
  let (and+) x y = Term.(const (fun x y -> x, y) $ x $ y) in
  let+
    authentication = authentication and+
    base_uri = base_uri and+
    bearer = bearer and+
    content = content and+
    content_type = content_type and+
    data = data and+
    digest = digest and+
    dry_run = dry_run and+
    headers = headers and+
    json = json and+
    pass = pass and+
    path = path and+
    query = query and+
    raw_form = raw_form and+
    raw_path = raw_path and+
    raw_query = raw_query and+
    user = user and+
    verb = verb and+
    () = Term.(const ())
  in
  let authentication =
    match authentication with
    | Some x -> Some ((Raw : authentication_method), x)
    | None ->
    match bearer with
    | Some x -> Some (Bearer, x)
    | None ->
    let auth = if digest then Digest else Basic in
    match user with
    | Some x -> Some (auth, x)
    | None -> None
  in
  let body =
    match content with
    | Some content -> Some (Raw content)
    | None ->
    match json with
    | Some json -> Some (JSON json)
    | None ->
    match data with
    | _ :: _ -> Some (Form data)
    | [] -> None
  in
  siesta {
    authentication;
    base_uri;
    body;
    content_type;
    dry_run;
    headers;
    pass;
    path;
    query;
    raw_form;
    raw_path;
    raw_query;
    verb;
  }

[@@@alert "-deprecated"]

let cmd =
  let doc = "call REST APIs without a hassle" in
  let info = Term.info "siesta" ~version:"%%VERSION%%" ~doc in
  siesta_t, info

let main () = Term.exit (Term.eval cmd)

let () = main ()
