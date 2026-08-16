package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/dom-raven/eksuvia/internal/store"
)

// EKS exception names. The AWS SDKs dispatch on the x-amzn-ErrorType header and
// on the message body, so both must be present and correctly spelled for a
// caller's error handling -- retries, waiters, "not found" branches -- to
// behave the way it would against AWS.
const (
	ErrClientException             = "ClientException"
	ErrResourceNotFound            = "ResourceNotFoundException"
	ErrResourceInUse               = "ResourceInUseException"
	ErrInvalidParameter            = "InvalidParameterException"
	ErrInvalidRequest              = "InvalidRequestException"
	ErrResourceLimitExceeded       = "ResourceLimitExceededException"
	ErrServerException             = "ServerException"
	ErrUnsupportedAvailabilityZone = "UnsupportedAvailabilityZoneException"
)

type errorBody struct {
	Message string `json:"message"`
	// The EKS exception shapes carry these alongside the message; the SDKs
	// surface them on the typed error.
	ClusterName   string `json:"clusterName,omitempty"`
	NodegroupName string `json:"nodegroupName,omitempty"`
	AddonName     string `json:"addonName,omitempty"`
}

func writeError(w http.ResponseWriter, status int, errType, message string) {
	writeErrorDetail(w, status, errType, errorBody{Message: message})
}

func writeErrorDetail(w http.ResponseWriter, status int, errType string, body errorBody) {
	w.Header().Set("Content-Type", "application/json")
	// Both headers are set because different SDK generations read different
	// ones; AWS itself sends both.
	w.Header().Set("x-amzn-ErrorType", errType)
	w.Header().Set("x-amzn-errortype", errType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeStoreError maps a store error onto the matching EKS exception.
func writeStoreError(w http.ResponseWriter, err error) {
	var notFound *store.ErrNotFound
	if errors.As(err, &notFound) {
		writeErrorDetail(w, http.StatusNotFound, ErrResourceNotFound, errorBody{
			Message:     "No cluster found for name: " + notFound.Name + ".",
			ClusterName: notFound.Name,
		})
		return
	}
	var exists *store.ErrAlreadyExists
	if errors.As(err, &exists) {
		writeErrorDetail(w, http.StatusConflict, ErrResourceInUse, errorBody{
			Message:     "Cluster already exists with name: " + exists.Name,
			ClusterName: exists.Name,
		})
		return
	}
	writeError(w, http.StatusInternalServerError, ErrServerException, err.Error())
}

// decodeJSON reads a JSON request body, reporting a malformed body as an EKS
// client error rather than a 500.
func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	if r.Body == nil {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter, "request body is required")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(out); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter, "malformed request body: "+err.Error())
		return false
	}
	return true
}
