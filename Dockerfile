FROM golang

WORKDIR /usr/local/src
COPY ./server.go ./server.go
RUN go get -u github.com/lib/pq && go build .

CMD ["/usr/local/src/src"]
