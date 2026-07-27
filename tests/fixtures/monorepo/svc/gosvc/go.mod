module example.com/svc/gosvc

go 1.21

require (
	github.com/stretchr/testify v1.8.4
	github.com/spf13/cobra v1.7.0
	golang.org/x/sync v0.0.0-20210101120000-abcdef123456
	github.com/docker/docker v20.10.7+incompatible
	github.com/davecgh/go-spew v1.1.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require example.com/internal/helpers v0.4.0

require github.com/olddep/pkg v1.0.0

replace example.com/internal/helpers => ../helpers

replace github.com/olddep/pkg => github.com/newdep/pkg v1.4.0

exclude github.com/stretchr/testify v1.9.0
