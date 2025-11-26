package storage_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/kashguard/go-kms/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgreSQLStore_SaveAndGetKeyMetadata(t *testing.T) {
	test.WithTestDatabase(t, func(db *sql.DB) {
		ctx := context.Background()
		store := storage.NewPostgreSQLStore(db)

		keyMetadata := &storage.KeyMetadata{
			KeyID:       "test-key-1",
			Alias:       "test-key",
			Description: "Test key for unit testing",
			KeyType:     "AES_256",
			KeyState:    "Enabled",
			HSMHandle:   "handle-123",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		// Save key metadata
		err := store.SaveKeyMetadata(ctx, keyMetadata)
		require.NoError(t, err)

		// Get key metadata
		retrieved, err := store.GetKeyMetadata(ctx, "test-key-1")
		require.NoError(t, err)
		assert.Equal(t, keyMetadata.KeyID, retrieved.KeyID)
		assert.Equal(t, keyMetadata.Alias, retrieved.Alias)
		assert.Equal(t, keyMetadata.Description, retrieved.Description)
		assert.Equal(t, keyMetadata.KeyType, retrieved.KeyType)
		assert.Equal(t, keyMetadata.KeyState, retrieved.KeyState)
	})
}

func TestPostgreSQLStore_ListKeyMetadata(t *testing.T) {
	test.WithTestDatabase(t, func(db *sql.DB) {
		ctx := context.Background()
		store := storage.NewPostgreSQLStore(db)

		// Create multiple keys
		for i := 1; i <= 3; i++ {
			keyMetadata := &storage.KeyMetadata{
				KeyID:     "test-key-" + string(rune('0'+i)),
				Alias:     "test-key-" + string(rune('0'+i)),
				KeyType:   "AES_256",
				KeyState:  "Enabled",
				HSMHandle: "handle-" + string(rune('0'+i)),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			err := store.SaveKeyMetadata(ctx, keyMetadata)
			require.NoError(t, err)
		}

		// List keys
		keys, err := store.ListKeyMetadata(ctx, &storage.KeyFilter{
			Limit:  10,
			Offset: 0,
		})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(keys), 3)
	})
}
