package i18n

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectLanguage(t *testing.T) {
	// 1. Default German when header is empty
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if lang := DetectLanguage(req); lang != LangDE {
		t.Errorf("Expected default %s, got %s", LangDE, lang)
	}

	// 2. Detected German from Accept-Language
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "de-DE,de;q=0.9,en;q=0.8")
	if lang := DetectLanguage(req); lang != LangDE {
		t.Errorf("Expected detected %s, got %s", LangDE, lang)
	}

	// 3. Detected English from Accept-Language
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if lang := DetectLanguage(req); lang != LangEN {
		t.Errorf("Expected %s, got %s", LangEN, lang)
	}

	// 4. Cookie overrides Accept-Language
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "de-DE,de;q=0.9")
	req.AddCookie(&http.Cookie{Name: "lang", Value: "en"})
	if lang := DetectLanguage(req); lang != LangEN {
		t.Errorf("Expected cookie override %s, got %s", LangEN, lang)
	}

	// 5. Query param overrides Cookie
	req = httptest.NewRequest(http.MethodGet, "/?lang=de", nil)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "en"})
	if lang := DetectLanguage(req); lang != LangDE {
		t.Errorf("Expected query param override %s, got %s", LangDE, lang)
	}
}

func TestTranslations(t *testing.T) {
	if T(LangDE, "nav.clients") != "Clients" {
		t.Errorf("Unexpected DE translation: %s", T(LangDE, "nav.clients"))
	}
	if T(LangEN, "nav.clients") != "Clients" {
		t.Errorf("Unexpected EN translation: %s", T(LangEN, "nav.clients"))
	}

	if T(LangDE, "common.logout") != "Abmelden" {
		t.Errorf("Unexpected DE translation: %s", T(LangDE, "common.logout"))
	}
	if T(LangEN, "common.logout") != "Log Out" {
		t.Errorf("Unexpected EN translation: %s", T(LangEN, "common.logout"))
	}

	// Formatted argument test
	if T(LangDE, "logs.hist_subtitle", 30) != "Dauerhaft gespeicherte Authentifizierungsanfragen (Vorhaltezeit: 30 Tage)" {
		t.Errorf("Formatting failed in DE")
	}
	if T(LangEN, "logs.hist_subtitle", 30) != "Permanently stored authentication requests (Retention: 30 days)" {
		t.Errorf("Formatting failed in EN")
	}
}
