package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/auth"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

type adminInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

func readAdminInput(input io.Reader, confirm bool) (adminInput, error) {
	body, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil || len(body) > 4096 {
		return adminInput{}, errors.New("local administrator input must be at most 4096 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var value adminInput
	if err := decoder.Decode(&value); err != nil {
		return adminInput{}, errors.New("local administrator input must be a JSON object with the documented fields")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return adminInput{}, errors.New("local administrator input must contain exactly one JSON object")
	}
	if confirm {
		if value.Code == "" || value.Username != "" || value.Password != "" {
			return adminInput{}, errors.New("MFA confirmation accepts only a code")
		}
	} else if value.Username == "" || value.Password == "" || value.Code != "" {
		return adminInput{}, errors.New("administrator setup and reset require username and password")
	}
	return value, nil
}

func runAdmin(ctx context.Context, c config.Server, logger *slog.Logger) int {
	var value adminInput
	var err error
	if !c.AdminLink {
		value, err = readAdminInput(os.Stdin, c.AdminConfirm)
		if err != nil {
			logger.Error("administrator operation failed", "reason", err.Error())
			return 2
		}
	}
	operationCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	store, err := storage.Open(operationCtx, c.Database)
	if err != nil {
		logger.Error("administrator operation failed", "reason", err.Error())
		return 1
	}
	defer store.Close()
	service, err := auth.New(operationCtx, store, c.EncryptionKey)
	if err != nil {
		logger.Error("administrator operation failed", "reason", err.Error())
		return 1
	}
	var output any
	if c.AdminLink {
		// The install command turns the token into the link.
		var token string
		var expires time.Time
		token, expires, err = service.NewSetupLink(operationCtx)
		output = struct {
			Token     string `json:"token"`
			ExpiresAt int64  `json:"expires_at"`
		}{token, expires.Unix()}
	} else if c.AdminConfirm {
		err = service.Confirm(operationCtx, value.Code)
		output = struct {
			Status string `json:"status"`
		}{Status: "confirmed"}
	} else {
		output, err = service.Setup(operationCtx, value.Username, value.Password, c.AdminReset)
	}
	if err != nil {
		logger.Error("administrator operation failed", "reason", err.Error())
		return 1
	}
	// This local-only operation deliberately returns provisioning material once.
	// It is not an HTTP endpoint, environment value, command argument, or log.
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		logger.Error("cannot write local administrator result")
		return 1
	}
	return 0
}
