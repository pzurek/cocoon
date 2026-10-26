package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

const maxReservedSigningKeys = 10_000

var (
	errReservationCapacity = errors.New("signing key reservation capacity reached")
	errReservationRate     = errors.New("signing key generation rate exceeded")
)

type ServerReserveSigningKeyRequest struct {
	Did *string `json:"did"`
}

type ServerReserveSigningKeyResponse struct {
	SigningKey string `json:"signingKey"`
}

func (s *Server) handleServerReserveSigningKey(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerReserveSigningKey")

	mediaType, _, err := mime.ParseMediaType(e.Request().Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return e.JSON(http.StatusUnsupportedMediaType, map[string]string{"error": "InvalidRequest"})
	}
	body := http.MaxBytesReader(e.Response(), e.Request().Body, 16*1024)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return e.JSON(http.StatusRequestEntityTooLarge, map[string]string{"error": "InvalidRequest"})
		}
		return helpers.InputError(e, nil)
	}
	var req *ServerReserveSigningKeyRequest
	if err := json.Unmarshal(data, &req); err != nil || req == nil {
		return helpers.InputError(e, nil)
	}
	if req.Did != nil {
		if _, err := syntax.ParseDID(*req.Did); err != nil {
			return helpers.InputError(e, nil)
		}
	}

	unlock := s.lockRepoWrite("reserved-keys")
	defer unlock()
	if s.reservationLimiter == nil {
		s.reservationLimiter = rate.NewLimiter(rate.Every(time.Second), 5)
	}
	var keyDid string
	err = s.db.Transaction(ctx, func(tx *db.DB) error {
		// Serialize before reading: PostgreSQL needs a table lock even when
		// there are no reservations; SQLite needs writer intent before reads.
		lock := "UPDATE reserved_keys SET key_did = key_did WHERE 1 = 0"
		if tx.Client().Dialector.Name() == "postgres" {
			lock = "LOCK TABLE reserved_keys IN EXCLUSIVE MODE"
		}
		if err := tx.Exec(ctx, lock, nil).Error; err != nil {
			return err
		}
		if req.Did != nil {
			var existing models.ReservedKey
			result := tx.Client().Where("did = ?", *req.Did).Order("created_at, key_did").Limit(1).Find(&existing)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 0 {
				keyDid = existing.KeyDid
				return nil
			}
		}
		var count int64
		if err := tx.Client().Model(&models.ReservedKey{}).Count(&count).Error; err != nil {
			return err
		}
		if count >= maxReservedSigningKeys {
			return errReservationCapacity
		}
		if !s.reservationLimiter.Allow() {
			return errReservationRate
		}
		k, err := atcrypto.GeneratePrivateKeyK256()
		if err != nil {
			return err
		}
		pubKey, err := k.PublicKey()
		if err != nil {
			return err
		}
		keyDid = pubKey.DIDKey()
		return tx.Create(ctx, &models.ReservedKey{KeyDid: keyDid, Did: req.Did, PrivateKey: k.Bytes(), CreatedAt: time.Now().UTC()}, nil).Error
	})
	if errors.Is(err, errReservationCapacity) {
		return e.JSON(http.StatusServiceUnavailable, map[string]string{"error": "ReservationCapacityExceeded", "message": "New reservations are unavailable; existing reservations remain usable."})
	}
	if errors.Is(err, errReservationRate) {
		e.Response().Header().Set("Retry-After", "1")
		return e.JSON(http.StatusTooManyRequests, map[string]string{"error": "RateLimitExceeded"})
	}
	if err != nil {
		logger.Error("error reserving signing key", "error", err)
		return helpers.ServerError(e, nil)
	}
	return e.JSON(200, ServerReserveSigningKeyResponse{
		SigningKey: keyDid,
	})
}

func (s *Server) getReservedKey(ctx context.Context, keyDidOrDid string) (*models.ReservedKey, error) {
	var reservedKey models.ReservedKey

	err := s.db.Client().WithContext(ctx).Where("key_did = ?", keyDidOrDid).Take(&reservedKey).Error
	if err == nil {
		return &reservedKey, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	err = s.db.Client().WithContext(ctx).Where("did = ?", keyDidOrDid).Order("created_at, key_did").Take(&reservedKey).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &reservedKey, nil
}
