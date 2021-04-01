go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.25.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.0.0
go get google.golang.org/grpc@v1.34.0
go install github.com/LLKennedy/mercury/cmd/protoc-gen-mercury@v0.9.0
go install github.com/LLKennedy/protoc-gen-tsjson@v0.5.0

$CurrentDirectory = $(Resolve-Path -Path .).Path + "/"
$ProtoPath = $CurrentDirectory + "api/proto/"
$TSJSONPath = $CurrentDirectory + "api/node_modules/@llkennedy/protoc-gen-tsjson/"
$Directory = $ProtoPath + "*"
$IncludeRule = "*.proto"
$GoPBPath = "./api/padlockpb"
$TSPBPath = "./api/src"
$ProtoFiles = Get-ChildItem -path $Directory -Include $IncludeRule
foreach ($file in $ProtoFiles) {
	protoc --proto_path=$ProtoPath --proto_path=$TSJSONPath --go_out=paths=source_relative:$GoPBPath --go-grpc_out=paths=source_relative:$GoPBPath --tsjson_out=$TSPBPath --mercury_out=$TSPBPath $file.FullName
}

go build $GoPBPath
go mod tidy