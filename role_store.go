package bearer

import (
	"cmp"
	"context"
)

type RoleStore[T cmp.Ordered] interface {
	RoleByEmail(ctx context.Context, email string) (T, error)
}
