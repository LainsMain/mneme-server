package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/lainsmain/mneme-server/internal/store"
)

func TestAuthenticatedObjectAndManifestRoundTrip(t *testing.T) {
	dataStore, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	token, _, err := dataStore.CreateToken(context.Background(), "test phone")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(
		dataStore,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithGarbageCollectionMinimumAge(0),
	).Handler())
	defer server.Close()

	health, err := http.Get(server.URL + "/v1/health")
	if err != nil || health.StatusCode != http.StatusOK {
		t.Fatalf("health: status=%v error=%v", health.Status, err)
	}
	health.Body.Close()

	payload := []byte("opaque encrypted diary object")
	digest := sha256.Sum256(payload)
	hash := hex.EncodeToString(digest[:])
	upload := authenticatedRequest(t, http.MethodPut, server.URL+"/v1/objects/"+hash, token, payload)
	if upload.StatusCode != http.StatusCreated {
		t.Fatalf("upload returned %s: %s", upload.Status, readBody(upload.Body))
	}
	upload.Body.Close()

	download := authenticatedRequest(t, http.MethodGet, server.URL+"/v1/objects/"+hash, token, nil)
	if got := readBody(download.Body); got != string(payload) {
		t.Fatalf("downloaded %q, want %q", got, payload)
	}
	download.Body.Close()

	manifestPayload := []byte("encrypted manifest")
	request, err := http.NewRequest(http.MethodPut, server.URL+"/v1/manifests/test-device", bytes.NewReader(manifestPayload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Mneme-Revision", "1")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("manifest upload returned %s: %s", response.Status, readBody(response.Body))
	}
	response.Body.Close()

	references := authenticatedRequest(t, http.MethodPut,
		server.URL+"/v1/manifests/test-device/history/1/references", token,
		[]byte(`{"objectHashes":["`+hash+`"]}`),
	)
	if references.StatusCode != http.StatusOK {
		t.Fatalf("references returned %s: %s", references.Status, readBody(references.Body))
	}
	references.Body.Close()

	manifest := authenticatedRequest(t, http.MethodGet, server.URL+"/v1/manifests/test-device", token, nil)
	if got := readBody(manifest.Body); got != string(manifestPayload) {
		t.Fatalf("manifest %q, want %q", got, manifestPayload)
	}
	manifest.Body.Close()

	history := authenticatedRequest(t, http.MethodGet, server.URL+"/v1/manifests/test-device/history", token, nil)
	if history.StatusCode != http.StatusOK {
		t.Fatalf("history returned %s", history.Status)
	}
	var snapshots []store.Manifest
	if err := json.NewDecoder(history.Body).Decode(&snapshots); err != nil {
		t.Fatal(err)
	}
	history.Body.Close()
	if len(snapshots) != 1 || !snapshots[0].ReferencesComplete {
		t.Fatalf("unexpected history: %#v", snapshots)
	}

	storage := authenticatedRequest(t, http.MethodGet, server.URL+"/v1/storage", token, nil)
	if storage.StatusCode != http.StatusOK {
		t.Fatalf("storage returned %s", storage.Status)
	}
	storage.Body.Close()

	cleanup := authenticatedRequest(t, http.MethodPost, server.URL+"/v1/storage/gc", token,
		[]byte(`{"keepManifestsPerDevice":30}`),
	)
	if cleanup.StatusCode != http.StatusOK {
		t.Fatalf("cleanup returned %s: %s", cleanup.Status, readBody(cleanup.Body))
	}
	cleanup.Body.Close()
}

func TestManifestHistoryAndGarbageCollection(t *testing.T) {
	dataStore, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	ctx := context.Background()
	put := func(value string) string {
		payload := []byte(value)
		digest := sha256.Sum256(payload)
		hash := hex.EncodeToString(digest[:])
		if _, err := dataStore.PutObject(ctx, hash, bytes.NewReader(payload), 1024); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	photoHash := put("photo")
	for revision := int64(1); revision <= 4; revision++ {
		manifestHash := put("manifest-" + strconv.FormatInt(revision, 10))
		if err := dataStore.PutManifest(ctx, "phone", revision, manifestHash); err != nil {
			t.Fatal(err)
		}
		if err := dataStore.PutManifestReferences(ctx, "phone", revision, []string{photoHash}); err != nil {
			t.Fatal(err)
		}
	}
	orphanHash := put("orphan")
	time.Sleep(time.Millisecond)
	result, err := dataStore.CollectGarbage(ctx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if result.PrunedManifestCount != 2 || result.DeletedObjectCount != 3 {
		t.Fatalf("unexpected collection result: %#v", result)
	}
	if _, err := dataStore.OpenObject(orphanHash); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan was not removed: %v", err)
	}
	if _, err := dataStore.OpenObject(photoHash); err != nil {
		t.Fatalf("referenced photo was removed: %v", err)
	}
}

func TestProtectedEndpointRejectsMissingToken(t *testing.T) {
	dataStore, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	server := httptest.NewServer(New(dataStore, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer server.Close()

	response, err := http.Get(server.URL + "/v1/vault/status")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %s, want 401 Unauthorized", response.Status)
	}
}

func authenticatedRequest(t *testing.T, method, url, token string, body []byte) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func readBody(body io.Reader) string {
	value, _ := io.ReadAll(body)
	return string(value)
}
