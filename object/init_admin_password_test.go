package object

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestInitialBuiltInAdminPasswordFreshInvalidFileWritesNothing(t *testing.T) {
	if ormer != nil {
		t.Fatal("refusing a test with an initialized database")
	}
	for _, test := range []struct {
		name string
		data []byte
		want error
	}{
		{name: "missing", want: errInitialBuiltInAdminRead},
		{name: "invalid", data: []byte(strings.Repeat("A", 31) + " "), want: errInitialBuiltInAdminCharacters},
		{name: "extra-final-newline", data: []byte(strings.Repeat("A", 32) + "\n\n"), want: errInitialBuiltInAdminCharacters},
		{name: "oversized", data: []byte(strings.Repeat("A", 75)), want: errInitialBuiltInAdminLength},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "initial-password")
			if test.data != nil {
				if err := os.WriteFile(path, test.data, 0o600); err != nil {
					t.Fatal("cannot create owned fixture")
				}
			}
			writes := 0
			err := withInitialBuiltInAdminPassword(path, func(owner, name string) (*Organization, error) {
				if owner != "admin" || name != "built-in" {
					t.Fatal("preflight inspected the wrong organization")
				}
				return nil, nil
			}, readInitialBuiltInAdminPassword, func(string) { writes++ })
			if !errors.Is(err, test.want) || writes != 0 {
				t.Fatal("invalid fresh bootstrap reached a seed write or changed its static error")
			}
		})
	}
}

func TestInitialBuiltInAdminPasswordExactNormalization(t *testing.T) {
	for _, size := range []int{32, 72} {
		password := strings.Repeat("!", size)
		for _, ending := range []string{"", "\n", "\r\n"} {
			actual, err := normalizeInitialBuiltInAdminPassword([]byte(password + ending))
			if err != nil || actual != password {
				t.Fatal("valid boundary password or final newline normalization changed")
			}
		}
	}
	valid := strings.Repeat("A", 32)
	for _, invalid := range [][]byte{
		[]byte(strings.Repeat("A", 31)),
		[]byte(strings.Repeat("A", 73)),
		[]byte(" " + valid),
		[]byte(valid + " "),
		[]byte(valid + "\r"),
		[]byte(valid + "\n\n"),
		[]byte(valid + "\r\n\n"),
		[]byte(valid[:15] + "\n" + valid[16:]),
		append([]byte(valid), 0),
		append([]byte(valid), 0x7f),
		append([]byte(valid), 0xc3, 0xa9),
	} {
		if actual, err := normalizeInitialBuiltInAdminPassword(invalid); err == nil || actual != "" {
			t.Fatal("invalid bytes were trimmed or accepted")
		}
	}
}

func TestInitialBuiltInAdminPasswordBoundedFileAndSymlink(t *testing.T) {
	password := strings.Repeat("~", 72)
	path := filepath.Join(t.TempDir(), "password-value")
	if err := os.WriteFile(path, []byte(password+"\r\n"), 0o600); err != nil {
		t.Fatal("cannot create owned fixture")
	}
	actual, err := readInitialBuiltInAdminPassword(path)
	if err != nil || actual != password {
		t.Fatal("bounded read rejected a maximum-length value plus CRLF")
	}
	t.Run("secret-volume-style-symlink", func(t *testing.T) {
		link := filepath.Join(filepath.Dir(path), "mounted-key")
		if err := os.Symlink(path, link); err != nil {
			t.Skip("host cannot create an owned symlink fixture")
		}
		actual, err := readInitialBuiltInAdminPassword(link)
		if err != nil || actual != password {
			t.Fatal("normal secret-volume-style symlink was rejected")
		}
	})
}

func TestInitialBuiltInAdminPasswordFreshNativeUserAndHasher(t *testing.T) {
	password := strings.Repeat("!aZ9", 8)
	path := filepath.Join(t.TempDir(), "initial-password")
	if err := os.WriteFile(path, []byte(password+"\r\n"), 0o600); err != nil {
		t.Fatal("cannot create owned fixture")
	}
	organizationWrites, userWrites := 0, 0
	err := withInitialBuiltInAdminPassword(path, func(string, string) (*Organization, error) { return nil, nil }, readInitialBuiltInAdminPassword, func(prepared string) {
		if prepared != password {
			t.Fatal("seeding did not receive the normalized file value")
		}
		organizationWrites++ // recording only; no DB is opened or initialized
		initBuiltInUser(prepared, func(owner, name string) (*User, error) {
			if owner != "built-in" || name != "admin" {
				t.Fatal("initialization selected another user")
			}
			return nil, nil
		}, func(user *User, language string) (bool, error) {
			if organizationWrites != 1 || user.Password != password || user.PasswordType != "" || user.Password == "123" || user.Owner != "built-in" || user.Name != "admin" || !user.IsAdmin || user.SignupApplication != "app-built-in" || language != "en" {
				t.Fatal("native AddUser input, identity or bootstrap order changed")
			}
			// Recording AddUser callback executes the exact native hasher called by
			// AddUser; actual DB persistence remains a separate first-boot test.
			organization := &Organization{Name: "built-in", PasswordType: "bcrypt", DefaultPassword: "unrelated-default"}
			user.UpdateUserPassword(organization)
			if user.Password == password || user.Password == "" || user.PasswordType != "bcrypt" || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
				t.Fatal("configured initial password did not follow the native bcrypt path")
			}
			userWrites++
			return true, nil
		})
	})
	if err != nil || organizationWrites != 1 || userWrites != 1 {
		t.Fatal("valid fresh bootstrap did not seed once")
	}
}

func TestInitialBuiltInAdminPasswordExistingOrganizationSkipsFile(t *testing.T) {
	organization := &Organization{Owner: "admin", Name: "built-in", PasswordType: "bcrypt", DefaultPassword: "unchanged-default", HasPrivilegeConsent: true}
	before := *organization
	reads, seedCalls := 0, 0
	err := withInitialBuiltInAdminPassword(filepath.Join(t.TempDir(), "missing"), func(string, string) (*Organization, error) { return organization, nil }, func(string) (string, error) {
		reads++
		return "", errInitialBuiltInAdminRead
	}, func(prepared string) {
		seedCalls++
		if prepared != "" {
			t.Fatal("existing organization received a replacement password")
		}
	})
	if err != nil || reads != 0 || seedCalls != 1 || !reflect.DeepEqual(before, *organization) {
		t.Fatal("existing organization read the file or changed state")
	}
	user := &User{Owner: "built-in", Name: "admin", Password: "unchanged-hash", DisplayName: "Existing admin"}
	userBefore := *user
	initBuiltInUser(strings.Repeat("A", 32), func(string, string) (*User, error) { return user, nil }, func(*User, string) (bool, error) {
		t.Fatal("existing user was recreated or reset")
		return false, nil
	})
	if !reflect.DeepEqual(userBefore, *user) {
		t.Fatal("existing user profile or password changed")
	}
}

func TestInitialBuiltInAdminPasswordUnsetKeepsNativePath(t *testing.T) {
	t.Setenv("initAdminPassword", "")
	t.Setenv("isDemoMode", "false")
	t.Setenv("dbName", "bootstrap-unit-test")
	seeds, users := 0, 0
	err := withInitialBuiltInAdminPassword("", func(string, string) (*Organization, error) {
		t.Fatal("unset feature performed a new organization preflight")
		return nil, nil
	}, func(string) (string, error) {
		t.Fatal("unset feature read a password file")
		return "", nil
	}, func(prepared string) {
		seeds++
		if prepared != "" {
			t.Fatal("unset feature replaced the native password source")
		}
		initBuiltInUser(prepared, func(string, string) (*User, error) { return nil, nil }, func(user *User, _ string) (bool, error) {
			if user.Password != "" || user.PasswordType != "" || user.DisplayName != "Admin" {
				t.Fatal("native AddUser input changed")
			}
			users++
			return true, nil
		})
	})
	if err != nil || seeds != 1 || users != 1 {
		t.Fatal("unset feature changed native bootstrap dispatch")
	}
}

func TestInitialBuiltInAdminPasswordStaticPreflightErrors(t *testing.T) {
	for _, lookupFails := range []bool{true, false} {
		reads, writes := 0, 0
		err := withInitialBuiltInAdminPassword("configured-file", func(string, string) (*Organization, error) {
			if lookupFails {
				return nil, errors.New("private underlying database payload")
			}
			return nil, nil
		}, func(string) (string, error) {
			reads++
			return "", errors.New("private underlying file payload")
		}, func(string) { writes++ })
		want, expectedReads := errInitialBuiltInAdminRead, 1
		if lookupFails {
			want, expectedReads = errInitialBuiltInAdminState, 0
		}
		if err != want || reads != expectedReads || writes != 0 {
			t.Fatal("preflight exposed a raw error or reached a write")
		}
	}
}

func TestInitialBuiltInAdminPasswordCreationFailureIsStatic(t *testing.T) {
	for _, failedLookup := range []bool{false, true} {
		func() {
			defer func() {
				if recovered := recover(); recovered != errInitialBuiltInAdminCreation {
					t.Fatal("configured initialization did not stop with a static creation error")
				}
			}()
			initBuiltInUser(strings.Repeat("A", 32), func(string, string) (*User, error) {
				if failedLookup {
					return nil, errors.New("private lookup payload")
				}
				return nil, nil
			}, func(*User, string) (bool, error) { return false, errors.New("private AddUser payload") })
		}()
	}
}
