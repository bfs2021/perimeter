// Package api holds the published description of the /api/v1 REST API.
package api

import _ "embed"

// OpenAPI is the OpenAPI 3.1 document served at /api/v1/openapi.yaml.
//
//go:embed openapi.yaml
var OpenAPI []byte
