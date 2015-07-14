package main

import (
	"fmt"
	"net/http"

	log "github.com/Sirupsen/logrus"      // fancy logging
	"github.com/dericofilho/goherokuname" // anonymous usernames
	"github.com/googollee/go-socket.io"   // websockets
	"github.com/nu7hatch/gouuid"          // session IDs
)

var (
	sockets  = make(map[socketio.Socket]string) // socket -> session token
	sessions = make(map[string]string)          // token  -> username
	// TODO: add storage for token -> list of sockets

	socketServer *socketio.Server // websocket connection manager
)

func init() {
	log.SetLevel(log.DebugLevel)

	// create a new socket server and make it available globally for config
	s, err := socketio.NewServer(nil)
	if err != nil {
		log.Fatal(err)
	}

	socketServer = s
}

// newSession will eventually return a valid session object, but for now
// it is just a string that represents the session token
func newSession() string {
	u, _ := uuid.NewV4()
	return u.String()
}

// newUser will eventually return a user object, but for now it is only the username
func newUser() string {
	return goherokuname.Haikunate()
}

// validateSessionToken checks if the token is currently connected to a user
// and if it is that means it is valid. More sophisticated validations and expiry
// will follow when I move this to real objects
func validateSessionToken(token string) (username string, found bool) {
	username, found = sessions[token]
	return
}

func main() {
	socketServer.On("connection", func(so socketio.Socket) {
		// everyboy joins the main room
		so.Join("all")

		// check if the client sent a session token along when connecting,
		// which means she is most certainly logged in already
		sessionToken := so.Request().FormValue("token")

		log.WithFields(log.Fields{
			"socket": so.Id(),
			"token":  sessionToken,
		}).Debugln("connect")

		// validate the token and generate a new one should it be invalid
		if user, valid := validateSessionToken(sessionToken); valid {
			so.Join("logged-in")
			so.Emit("log", fmt.Sprintf("You are logged in as %q", user))

			// TODO: attach this SOCKET to the already existing SESSION

		} else {
			// if there was no token sent we generate a new one and
			// send it back for the client to store for next time
			sessionToken = newSession()
			so.Emit("log", fmt.Sprint("new session token: ", sessionToken))

			// add an anonymous user to this session
			// (this overrides the "" in the 'user' variable returned by session validation)
			user = newUser()
			sessions[sessionToken] = user

			so.Emit("log", fmt.Sprintf("Your anonymous user is %s", user))

			so.Join("anon")
		}

		// associate this socket with the session we just created
		sockets[so] = sessionToken

		so.On("disconnection", func() {
			delete(sockets, so) // remove the connection from the pool

			log.WithField("socket", so.Id()).Debugln("disconnect")
		})
	})

	// a general socket error occured
	socketServer.On("error", func(so socketio.Socket, err error) {
		log.Println("error:", err)
	})

	// mount our socket server on the default socket.io path
	http.Handle("/socket.io/", socketServer)

	http.HandleFunc("/sessions", sessionsDebugHandler)

	// serve the static html (development only)
	http.Handle("/", http.FileServer(http.Dir("./")))

	// start the server
	log.Println("Serving at localhost:5000...")
	log.Fatal(http.ListenAndServe(":5000", nil)) // this is blocking
}

func sessionsDebugHandler(rw http.ResponseWriter, req *http.Request) {
	// active connections: ID, joined rooms and session token
	if len(sockets) == 0 {
		fmt.Fprintln(rw, "Nobody is currently connected :(")
	}

	for socket, sessionToken := range sockets {
		fmt.Fprintf(rw, "%s\t%q\t%s\n", socket.Id(), socket.Rooms(), sessionToken)
	}

	fmt.Fprintln(rw, "")

	// ALL sessions, connected or not
	for token, username := range sessions {
		fmt.Fprintf(rw, "%s\t%q\n", token, username)
	}
}
