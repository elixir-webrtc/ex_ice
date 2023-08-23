# Simple ICE Example

Run as:

```bash
elixir peer.exs <signalling-ip> <signalling-port>
```

`signalling-ip` defaults to 127.0.0.1
`signalling-port` defaults to 4000

You can use our simple [signalling server](../signalling_server)

## Protocol

peer.exs sends following messages:

* `credentials`

    ```json
    {
        "type": "credentials",
        "ufrag": "someufrag",
        "passwd": "somepasswd"
    }
    ```

* `candidate`

    ```json
    {
        "type": "candidate",
        "cand": "somecandidate"
    }
    ```

* `end_of_candidates`

    ```json
    {
        "type": "end_of_candidates"
    }
    ```


