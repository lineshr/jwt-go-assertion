#  jwt-go-assertion

### Install k6 and GO 

- https://k6.io/docs/getting-started/installation/
- https://go.dev/dl/


### Download below libraries to execute go-module and K6 test
```
go get github.com/kataras/jwt	
go get	github.com/pavel-v-chernykh/keystore-go/v4
go get go.k6.io/k6/js/modules
```

Before execute test need to copy Keystore.jks file in the source folder, program will read keystore and select certificate to sign JWT data. 

```
$ xk6 build --with xk6-compare=.
$ ../k6 run test.js
```
