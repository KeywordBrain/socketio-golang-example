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
	connections  = make(map[string]socketio.Socket)
	socketServer *socketio.Server
)

var signingKey = []byte("dfb943aa439f")

func init() {
	s, err := socketio.NewServer(nil)
	if err != nil {
		log.Fatal(err)
	}

	socketServer = s
}

func main() {
	socketServer.SetAllowRequest(func(req *http.Request) error {
		req.ParseForm()
		var userToken = req.Form.Get("token")

		// dump, err := httputil.DumpRequest(req, true)
		// log.Println(string(dump), err)

		log.Println("jwt.Parse")
		token, err := jwt.Parse(
			userToken,
			func(token *jwt.Token) (interface{}, error) {
				// Don't forget to validate the alg is what you expect:
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					log.Println("Unexpected signing method", token.Header["alg"])
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				log.Println("found key", string(signingKey))
				return signingKey, nil
			})

		log.Println("done jwt.Parse")

		if err == nil && token.Valid {
			return nil
		}

		return err

		// return errors.New("Invalid token")
	})

	socketServer.On("connection", func(so socketio.Socket) {
		log.Println("connected", so.Id())

		so.Join("all")
		connections[so.Id()] = so

		so.On("dataRequest", dataRequest)

		so.On("disconnection", func() {
			log.Println("disconnected", so.Id())
			delete(connections, so.Id())
		})

	})

	socketServer.On("error", func(so socketio.Socket, err error) {
		log.Println("error:", err)
	})

	http.Handle("/socket.io/", socketServer)
	http.Handle("/", http.FileServer(http.Dir("./")))
	http.HandleFunc("/send", sendHandler)
	http.HandleFunc("/auth", authHandler)

	http.HandleFunc("/connections", connectionsDebugHandler)

	log.Println("Serving at localhost:5000...")
	log.Fatal(http.ListenAndServe(":5000", nil))
}

func dataRequest(socket socketio.Socket, msg string) {
	// socket.Request().ParseForm()
	// dump, err := httputil.DumpRequest(socket.Request(), true)
	// log.Println(string(dump), err)
	// fmt.Println(socket.Request().Form)
	log.Println("dataReq", socket.Id(), msg)
}

func authHandler(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	u := req.Form.Get("u")
	p := req.Form.Get("p")

	if u == "admin" && p == "admin" {
		token := jwt.New(jwt.SigningMethodHS256)

		// Set some claims
		token.Claims["user"] = "admin"
		token.Claims["userID"] = 1
		token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

		// Sign and get the complete encoded token as a string
		tokenString, err := token.SignedString(signingKey)

		fmt.Fprintf(rw, "%s \t %s", tokenString, err)
	}
}

func sendHandler(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	key := req.Form.Get("key")

	so, found := connections[key]
	if found == false {
		fmt.Fprintln(rw, "Session not found")
		return
	}

	so.Emit("currentTime", time.Now().UnixNano())
	socketServer.BroadcastTo("all", "hello", "Hi everyone!")

	fmt.Fprintln(rw, key)
}

func connectionsDebugHandler(rw http.ResponseWriter, req *http.Request) {
	for id, so := range connections {
		fmt.Fprintf(rw, "%s\t%q\n", id, so.Rooms())
	}
}
