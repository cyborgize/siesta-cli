open Devkit
open ExtLib

let _opt_str x = Option.default "NONE" x

type authentication_method =
  | Raw
  | Basic
  | Bearer
  | Digest

type authentication =
  | Auth of authentication_method * string
  | Auth_pass of authentication_method * string

type form_data = (string * string option) list

type body =
  | Raw of string
  | Form of form_data
  | JSON of string

type config = {
  authentication : authentication option;
  base_uri : string;
  body : body option;
  content_type : string option;
  dry_run : bool;
  pass : string;
  path : string list;
  query : form_data;
  raw_form : bool;
  raw_path : bool;
  raw_query : bool;
  verb : Web.http_action;
}

let siesta { authentication; base_uri; body; content_type; dry_run; pass; path; query; raw_form; raw_path; raw_query; verb; } =
  Lwt_main.run @@
  let add_type type_ map value = String.concat " " [ type_; map value; ] in
  let basic = add_type "Basic" Digest.(to_hex $ string) in
  let bearer = add_type "Bearer" Fun.id in
  let return_pass map1 map2 name =
    let lines = Lwt_process.pread_lines ("", [| pass; name; |]) in
    let%lwt lines = map1 lines in
    Lwt.wrap1 map2 lines
  in
  let%lwt authentication =
    match authentication with
    | None -> Lwt.return_none
    | Some authentication ->
    match authentication with
    | Auth (Raw, x) -> Lwt.return_some x
    | Auth (Basic, x) -> Lwt.return_some (basic x)
    | Auth (Bearer, x) -> Lwt.return_some (bearer x)
    | Auth (Digest, _x) -> Exn.fail "FIXME auth digest not implemented"
    | Auth_pass (Raw, x) -> return_pass Lwt_stream.get Fun.id x
    | Auth_pass (Basic, x) -> return_pass Lwt_stream.to_list (fun x -> Some (basic (String.concat ":" x))) x
    | Auth_pass (Bearer, x) -> return_pass Lwt_stream.next (some $ basic) x
    | Auth_pass (Digest, _x) -> Exn.fail "FIXME auth-pass digest not implemented"
  in
  let authentication = Option.map ((^) "Authentication: ") authentication in
  let headers = List.filter_map Fun.id [ authentication; ] in
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
  let body =
    match body with
    | None -> None
    | Some body ->
    let raw default_content_type content = Some (`Raw (Option.default default_content_type content_type, content)) in
    match body with
    | Raw _ -> Exn.fail "FIXME raw body not implemented"
    | Form x -> raw "application/x-www-form-urlencoded" (encode_query encode_form_component x)
    | JSON x -> raw "application/json" x
  in
  match dry_run with
  | true ->
    let%lwt () = Lwt_io.eprintlf "siesta: %s %s" (Web.string_of_http_action verb) full_uri in
    Lwt.return_unit
  | false ->
  match%lwt Web.http_request_lwt' ~headers ?body verb full_uri with
  | `Ok (code, s) -> Lwt_io.eprintlf "siesta: %d %s" code s
  | `Error code -> Lwt_io.eprintlf "siesta: curl error (%d) %s" (Curl.int_of_curlCode code) (Curl.strerror code)

open Cmdliner

let key_and_value =
  let key_and_value = Arg.(pair ~sep:'=' string string) in
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
  Arg.(value & opt (some string) None & info ["a"; "auth"] ~docv:"AUTH" ~doc)

let authentication_pass =
  let doc = "Specify the raw authentication using the value retrieved from the password manager." in
  Arg.(value & opt (some string) None & info ["A"; "auth-pass"] ~docv:"AUTH_PASS" ~doc)

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
  Arg.(value & opt (some string) None & info ["b"; "bearer"] ~docv:"BEARER" ~doc)

let bearer_pass =
  let doc = "Specify the bearer token for OAuth2 server authentication using the value retrieved from the password manager." in
  Arg.(value & opt (some string) None & info ["B"; "bearer-pass"] ~docv:"BEARER_PASS" ~doc)

let content =
  let doc = "Specify the content for the API call." in
  Arg.(value & opt (some string) None & info ["c"; "content"] ~docv:"CONTENT" ~doc)

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

let json =
  let doc = "Specify the json data for the API call." in
  Arg.(value & opt (some string) None & info ["j"; "json"] ~docv:"JSON" ~doc)

let pass =
  let doc = "Specify the password manager program to use." in
  Arg.(value & opt string "pass" & info ["p"; "pass"] ~docv:"PASS" ~doc)

let path =
  let doc = "Specify the HTTP request path for the API call." in
  Arg.(value & pos_right 1 string [] & info [] ~docv:"API_PATH" ~doc)

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
  Arg.(value & opt (some string) None & info ["u"; "user"] ~docv:"USERAUTH" ~doc)

let user_pass =
  let doc = "Specify the user authentication using the value retrieved from the password manager." in
  Arg.(value & opt (some string) None & info ["U"; "user-pass"] ~docv:"USERAUTH_PASS" ~doc)

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
    authentication_pass = authentication_pass and+
    base_uri = base_uri and+
    bearer = bearer and+
    bearer_pass = bearer_pass and+
    content = content and+
    content_type = content_type and+
    data = data and+
    digest = digest and+
    dry_run = dry_run and+
    json = json and+
    pass = pass and+
    path = path and+
    query = query and+
    raw_form = raw_form and+
    raw_path = raw_path and+
    raw_query = raw_query and+
    user = user and+
    user_pass = user_pass and+
    verb = verb and+
    () = Term.(const ())
  in
  let authentication =
    match authentication with
    | Some x -> Some (Auth (Raw, x))
    | None ->
    match authentication_pass with
    | Some x -> Some (Auth_pass (Raw, x))
    | None ->
    match bearer with
    | Some x -> Some (Auth (Bearer, x))
    | None ->
    match bearer_pass with
    | Some x -> Some (Auth_pass (Bearer, x))
    | None ->
    let auth = if digest then Digest else Basic in
    match user with
    | Some x -> Some (Auth (auth, x))
    | None ->
    match user_pass with
    | Some x -> Some (Auth_pass (auth, x))
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
  siesta { authentication; base_uri; body; content_type; dry_run; pass; path; query; raw_form; raw_path; raw_query; verb; }

[@@@alert "-deprecated"]

let cmd =
  let doc = "call REST APIs without a hassle" in
  let info = Term.info "siesta" ~version:"%%VERSION%%" ~doc in
  siesta_t, info

let main () = Term.exit (Term.eval cmd)

let () = main ()
