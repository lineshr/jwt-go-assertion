#  jwt-go-assertion

### Install k6 and GO 

### download below libraries to execute go-module and K6 test
```
go get github.com/kataras/jwt	
go get	github.com/pavel-v-chernykh/keystore-go/v4
go get go.k6.io/k6/js/modules
```

before execute test need to copy Keystore.jks file in the source folder. 
It will read keystore and select certificate to sign JWT data. 