package apiclient

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaginate_SinglePage_NilToken(t *testing.T) {
	got, err := paginate(context.Background(), func(ctx context.Context, tok *string) ([]int, *string, error) {
		assert.Nil(t, tok, "first call should pass nil token")

		return []int{1, 2, 3}, nil, nil
	})
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3}, got)
}

func TestPaginate_SinglePage_EmptyStringToken(t *testing.T) {
	// Server may return "" instead of null; treat both as "done".
	got, err := paginate(context.Background(), func(ctx context.Context, tok *string) ([]int, *string, error) {
		empty := ""

		return []int{7}, &empty, nil
	})
	require.NoError(t, err)
	assert.Equal(t, []int{7}, got)
}

func TestPaginate_MultiplePages(t *testing.T) {
	calls := 0
	got, err := paginate(context.Background(), func(ctx context.Context, tok *string) ([]int, *string, error) {
		calls++
		switch calls {
		case 1:
			assert.Nil(t, tok)
			next := "ptk_a"

			return []int{1, 2}, &next, nil
		case 2:
			require.NotNil(t, tok)
			assert.Equal(t, "ptk_a", *tok)
			next := "ptk_b"

			return []int{3, 4}, &next, nil
		case 3:
			require.NotNil(t, tok)
			assert.Equal(t, "ptk_b", *tok)

			return []int{5}, nil, nil
		}
		t.Fatalf("unexpected call %d", calls)

		return nil, nil, nil
	})
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3, 4, 5}, got)
	assert.Equal(t, 3, calls)
}

func TestPaginate_ErrorStopsLoop(t *testing.T) {
	calls := 0
	_, err := paginate(context.Background(), func(ctx context.Context, tok *string) ([]int, *string, error) {
		calls++
		if calls == 2 {
			return nil, nil, errors.New("boom")
		}
		next := "ptk"

		return []int{calls}, &next, nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
	assert.Equal(t, 2, calls)
}

func TestPaginate_RepeatedTokenAborted(t *testing.T) {
	// A buggy server that keeps handing back the same nextPageToken would
	// grow `all` without bound; catch the repeat and bail with a clear
	// error instead of OOMing the client.
	calls := 0
	_, err := paginate(context.Background(), func(ctx context.Context, tok *string) ([]int, *string, error) {
		calls++
		next := "stuck"

		return []int{calls}, &next, nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repeated pageToken")
	assert.Equal(t, 2, calls)
}

func TestPaginate_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	_, err := paginate(ctx, func(ctx context.Context, tok *string) ([]int, *string, error) {
		calls++

		return nil, nil, ctx.Err()
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
