namespace Net.Triplentry.Utilities

// Core functionality.
module OAuth =

    // Imports.
    open System
    open System.IO
    open System.Text
    open System.Security.Cryptography
    open Microsoft.FSharp.Control.WebClientExtensions
    open Microsoft.FSharp.Control.WebExtensions

    // Response status
    type Status = OK | ERROR

    // Parameter type.
    type Parameter = string * string

    // List of parameters type.
    type Parameters = Parameter list

    // Signature type.
    type SignatureType = PLAINTEXT | HMACSHA1 | RSASHA1

    // Http method type.
    type HttpMethod = GET | POST

    // Options.
    type Options = Option of SignatureType * HttpMethod

    // Request types.
    // GetRequest: ConsumerKey + ConsumerSecret
    // GetAccess: ConsumerKey + ConsumerSecret | token + tokenSecret | PIN Code
    // UseService: ConsumerKey + ConsumerSecret | accessToken + accessSecret
    type RequestType = 
        | GetRequestToken of (string * string)                                 
        | GetAccessToken of (string * string) * (string * string) * string      
        | UseWebService of (string * string) * (string * string)                

    // Inputs (url, RequestType, Parameters).
    type Inputs = Input of string * RequestType * Parameters

    // OAuth response string to tuple list.
    let ParseResponse (response : string) = 
        let splitEquals = fun (s : string) -> s.Split [|'='|]
        let createTuple = fun (x : string array) -> (x.[0], x.[1])
        response.Split [|'&'|] |> List.ofArray |> List.map (splitEquals >> createTuple)

    // Get value from tuple list by key.
    let GetResponseValue key keyValues = List.tryPick (fun (k, v) -> if k = key then Some v else None) keyValues

    // Returns the number of seconds since the UNIX Epoch.
    let private generateTimeStamp () = 
        ((DateTime.UtcNow - DateTime(1970, 1, 1)).TotalSeconds |> Convert.ToInt64).ToString ()

    // Generate a random string of characters of length specified by a parameter.
    let private generateNonce =
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        let random = Random()
        fun length -> 
            let n = [| for i in 0 .. length -> chars.[random.Next(chars.Length)] |]
            new String(n)

    // Encode URL String based on RFC3986 'percent encoding'.
    let private urlEncode s = Uri.EscapeDataString(s)

    // Get the string value for a signature type supplied.
    let private signatureTypeToString = function
        | PLAINTEXT -> "PLAINTEXT"
        | HMACSHA1 -> "HMAC-SHA1"
        | RSASHA1 -> "RSA-SHA1"

    // Get the string value for an http method supplied.
    let private httpMethodToString = function GET -> "GET" | POST -> "POST"

    // Lexographical sorter for key value, pairs.
    let private sorter x = List.sortBy (fun (key, value) -> key) x 

    // Concatenate a list of strings with a specified token.
    let private concatListWithToken token = function
        | x::y::xs -> String.Join(token, x::y::xs)
        | x::xs -> x + token
        | _ -> ""

    // Converts a Parameter type to a "key=value" string.
    let private parameterToKeyValue (key, value) = urlEncode key + "=" + urlEncode value

    // Converts a list of Parameters to suitable form for generating a signature in-line with the OAuth 1.0 spec.
    let private parametersToString parameterList = 
        parameterList |> List.map parameterToKeyValue |> concatListWithToken "&"

    // Generate parameters based on the type of request and associated request data.
    let private generateParameters signatureType requestType  =
        let baseParameters = [("oauth_nonce", generateNonce 16)
                              ("oauth_signature_method", signatureTypeToString signatureType)
                              ("oauth_timestamp", generateTimeStamp () )
                              ("oauth_version", "1.0")]
        match requestType with
        | GetRequestToken (consumer) -> 
            ("oauth_callback", "oob") ::
            ("oauth_consumer_key", fst consumer) :: baseParameters
        | GetAccessToken (consumer, request, pinCode) ->
            ("oauth_consumer_key", fst consumer) :: 
            ("oauth_token", fst request) ::
            ("oauth_verifier", pinCode) :: baseParameters
        | UseWebService (consumer, access) ->
            ("oauth_consumer_key", fst consumer) :: 
            ("oauth_token", fst access) :: baseParameters

    // Create can OAuth base string, as per the OAuth 1.0 spec. 
    let private generateSignatureData meth (url : string) parametersList =
        let encodedUrl = url |> urlEncode
        let parametersString = parametersList |> sorter |> parametersToString |> urlEncode
        httpMethodToString meth + "&" + encodedUrl + "&" + parametersString

    // Generate a signature, using the specified method, keys and base string.
    let private generateSignature signatureType keys (paramatersString : string) =
        let keysBytes = List.map urlEncode keys |> concatListWithToken "&" |> Encoding.ASCII.GetBytes
        match signatureType with
        | PLAINTEXT -> "Not implemented."
        | HMACSHA1 ->
            use hasher = new HMACSHA1 (keysBytes)
            paramatersString 
            |> Encoding.ASCII.GetBytes 
            |> hasher.ComputeHash 
            |> Convert.ToBase64String
            |> urlEncode
        | RSASHA1 -> "Not implemented."

    // Generate the http Authorisation header as per the OAuth1.0 specification.
    let private generateAuthHeader input options =
        let (Input (url, requestType, _) ) = input
        let (Option (signatureType, httpMethod) ) = options
        let paramaters = requestType |> generateParameters signatureType
        let signatureString = generateSignatureData httpMethod url paramaters
        printfn "%s" signatureString
        let keys =
            match requestType with
            | GetRequestToken (consumer) -> [snd consumer]  // We want the secrets -> (key/token, secret).
            | GetAccessToken (consumer, request, _) -> [snd consumer; snd request]
            | UseWebService (consumer, access) -> [snd consumer; snd access]
        let signature = generateSignature signatureType keys signatureString
        let paramatersWithSignature = ("oauth_signature", signature) :: paramaters 
        let encodeHeaderParameters parameters =
            match parameters with
            | [] -> ""
            | _ -> 
                let keyValuePairs = parameters |> List.map (fun (key, value) -> key + "=\"" + value + "\"")
                String.Join(", ", keyValuePairs)        
        let header = paramatersWithSignature |> sorter |> encodeHeaderParameters
        "OAuth " + header

    // Execute an asyncronous http GET/POST request.
    let private asyncWebRequest input options header =
        let (Input (url, _, parameters) ) = input
        let (Option (_, httpMethod) ) = options
        async {
            let webClient = new System.Net.WebClient ()
            let uri = System.Uri (url)
            let! result =
                webClient.Headers.Add ("Authorization", header)
                match httpMethod with
                | GET -> webClient.AsyncDownloadString (uri)
                | POST -> webClient.AsyncUploadString (uri, httpMethodToString httpMethod)
            return result 
        } 

    // Generic function used to access OAuth functionality. 
    // TODO: Deal with errors in a pretty way by parsing the response string.
    let private genericRequest input options =
        let header = generateAuthHeader input options
        let result = asyncWebRequest input options header
        let response = Async.Catch(result) |> Async.RunSynchronously
        match response with
        | Choice1Of2 html -> (OK, html)
        | Choice2Of2 e -> 
            let webException = e :?> System.Net.WebException
            let errorResponse = webException.Response :?> System.Net.HttpWebResponse
            let html = (new StreamReader(errorResponse.GetResponseStream ())).ReadToEnd()
            let errorString = e.Message + html
            (ERROR, errorString)

    // Helper aliases.
    // Returns OAuth request token or exception.
    let RequestToken inputs options = genericRequest inputs options

    // Returns OAuth access token or exception.
    let AccessToken input options = genericRequest input options

    // Returns result from chosen OAuth protected API endpoint.
    let UseService input options = genericRequest input options