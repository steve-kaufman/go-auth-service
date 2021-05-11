package jwtgen_test

import (
	"testing"

	"github.com/gomagedon/expectate"
	"github.com/steve-kaufman/go-auth-service/implementations/security/jwtgen"
)

type MockTimeGetter struct {
	Time float64
}

func (getter MockTimeGetter) GetTime() float64 {
	return getter.Time
}

func setupWithTime(time float64) *jwtgen.Generator {
	timeGetter := new(MockTimeGetter)
	timeGetter.Time = time

	return jwtgen.NewGenerator(jwtgen.Secrets{
		Access:  "fake_access_secret",
		Refresh: "fake_refresh_secret",
	}, timeGetter)
}

type JWTTest struct {
	name string

	mockTime             float64
	expectedAccessToken  string
	expectedRefreshToken string
}

var jwtTests = []JWTTest{
	{
		name: "With 42 seconds from epoch",

		mockTime:             42,
		expectedAccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjQyLCJ1c2VyX2lkIjoyLCJ1c2VybmFtZSI6ImpvaG5kb2UifQ.N2J5y-J-b3Wum-Gf4fl7oGDeEnhkUvX_NUA8dUkUyys",
		expectedRefreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjQyLCJ1c2VyX2lkIjoyLCJ1c2VybmFtZSI6ImpvaG5kb2UifQ.WSM3t95PMS9CzbrQ6wGTU1f7jneB9gq20sgts8fP1Sg",
	},
	{
		name: "With 100 seconds from epoch",

		mockTime:             100,
		expectedAccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjEwMCwidXNlcl9pZCI6MiwidXNlcm5hbWUiOiJqb2huZG9lIn0.6EVYHHi52dXG_TLOupfZdLfIGa1eMmaDhmSBZRKeuv0",
		expectedRefreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjEwMCwidXNlcl9pZCI6MiwidXNlcm5hbWUiOiJqb2huZG9lIn0.2A3BrDQK62ce4jd0YiwP5LzDXv036pswcNRvl8W_CMQ",
	},
}

func TestJWTGenerator_UsesTimeGetter(t *testing.T) {
	for _, tc := range jwtTests {
		t.Run(tc.name, func(t *testing.T) {
			expect := expectate.Expect(t)

			generator := setupWithTime(tc.mockTime)

			tokens, err := generator.GetTokens(2, "johndoe")
			expect(err).ToBe(nil)

			expect(tokens.AccessToken).ToBe(tc.expectedAccessToken)
			expect(tokens.RefreshToken).ToBe(tc.expectedRefreshToken)
		})
	}
}
