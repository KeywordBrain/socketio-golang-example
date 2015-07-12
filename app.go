package main

import (
	// "errors"
	"fmt"
	"log"
	"net/http"
	// "net/http/httputil"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/googollee/go-socket.io"
)

var (
	connections = make(map[string]socketio.Socket) // socket ID -> socket
	sessions    = make(map[socketio.Socket]string) // socket -> session token

	socketServer *socketio.Server // main connection manager
)

var signingKey = []byte("dfb943aa439f")

func init() {
	// start a new socket server and make it available globally
	s, err := socketio.NewServer(nil)
	if err != nil {
		log.Fatal(err)
	}

	socketServer = s
}

func main() {
	// socketServer.SetAllowRequest(func(req *http.Request) error {
	// 	req.ParseForm()
	// 	var userToken = req.Form.Get("token")

	// 	// dump, err := httputil.DumpRequest(req, true)
	// 	// log.Println(string(dump), err)

	// 	// log.Println("jwt.Parse")
	// 	token, err := jwt.Parse(
	// 		userToken,
	// 		func(token *jwt.Token) (interface{}, error) {
	// 			// Don't forget to validate the alg is what you expect:
	// 			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
	// 				log.Println("Unexpected signing method", token.Header["alg"])
	// 				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	// 			}
	// 			// log.Println("found key", string(signingKey))
	// 			return signingKey, nil
	// 		})

	// 	// log.Println("done jwt.Parse")

	// 	if err == nil && token.Valid {
	// 		return nil
	// 	}
	// 	// log.Println("Invalid request")

	// 	return err

	// 	// return errors.New("Invalid token")
	// })

	// called every time a client connects
	socketServer.On("connection", func(so socketio.Socket) {
		log.Println("[*]", so.Id())

		// store the connection ID with the socket
		connections[so.Id()] = so

		// everybody is part of 'all' and anonymous at first
		so.Join("all")
		so.Join("anonymous")

		// register handlers for different types of messages that clients can send
		so.On("graphql", graphQLWSHandler)
		so.On("login", loginWSHandler)

		// when a client disconnects remove the socket from active sessions
		// not sure how to handle clients that disconnect briefly; probably the
		// session shouldn’t be terminated but on the other hand the connection
		// is gone and a new one needs to be established.
		// This is probably the clients job by using the token to connect the socket
		// and then the server only needs to check it on new connections to not parse
		// the jwt for every message (or sth like that)
		so.On("disconnection", func() {
			log.Println("[x]", so.Id())
			delete(connections, so.Id()) // remove from connection pool
			delete(sessions, so)         // destroy active session, mainly for cleanup
		})

	})

	// a general socket error occured
	socketServer.On("error", func(so socketio.Socket, err error) {
		log.Println("error:", err)
	})

	// serve the static html
	http.Handle("/", http.FileServer(http.Dir("./")))

	// serve socket.io at the default path
	http.Handle("/socket.io/", socketServer)

	http.HandleFunc("/send", sendHandler)
	http.HandleFunc("/connections", connectionsDebugHandler)

	log.Println("Serving at localhost:5000...")
	log.Fatal(http.ListenAndServe(":5000", nil))
}

func graphQLWSHandler(socket socketio.Socket, msg string) {
	// check if the current connection is authenticated
	if _, found := sessions[socket]; !found {
		log.Printf("conn %s requested stuff but is not authenticated", socket.Id())
		return
	}

	log.Printf("GraphQL incoming on conn %s: %q", socket.Id(), msg)

	res := fmt.Sprintf("response for data request: %q", msg)
	socket.Emit("graphql-response", res)
}

// this will eventually be done through a GraphQL write
func loginWSHandler(socket socketio.Socket, msg string) {
	// validate credentials, just a string with a password for now
	// this will be parsed from GraphQL later on the main graphql
	// handler

	// TODO: don’t do this again if socket is currently authenticated
	log.Printf("Login request on socket %s with creds %q", socket.Id(), msg)
	if msg == "password" {
		log.Printf("Successfully authed conn %s for user with secret %s", socket.Id(), msg)

		// generate JWT for client and save to active sessions
		token := jwt.New(jwt.SigningMethodHS256)

		// Set some claims
		token.Claims["userID"] = 1
		token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

		// Sign and get the complete encoded token as a string
		tokenString, _ := token.SignedString(signingKey)

		// save token to session store
		sessions[socket] = tokenString

		// send token to client
		socket.Emit("token", tokenString)

		// user is no longer anonymous so we switch the room
		socket.Leave("anonymous")
		socket.Join("logged-in")

		return
	}

	log.Println("Login attempt failed")
}

// broadcasts the current time to all clients
func sendHandler(rw http.ResponseWriter, req *http.Request) {
	// req.ParseForm()
	// key := req.Form.Get("key")

	// so, found := connections[key]
	// if found == false {
	// 	fmt.Fprintln(rw, "Socket ID not found")
	// 	return
	// }

	msg := fmt.Sprintf("Broadcast! It is currently %s", time.Now())
	socketServer.BroadcastTo("all", "currentTime", msg)

	// fmt.Fprintln(rw, key)
	fmt.Fprintln(rw, "Sent current time to all clients")
}

func connectionsDebugHandler(rw http.ResponseWriter, req *http.Request) {
	for socketID, socket := range connections {
		var sessionToken string

		if token, found := sessions[socket]; found {
			sessionToken = token
		}
		fmt.Fprintf(rw, "%s\t%q\t%s\n", socketID, socket.Rooms(), sessionToken)
	}
}
