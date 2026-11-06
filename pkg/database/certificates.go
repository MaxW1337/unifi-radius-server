package database

import (
	"database/sql"
	"errors"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

var (
	ErrCertNotFound = errors.New("certificate not found")
)

// SaveCertificate persists a new or updated certificate.
func (db *DB) SaveCertificate(c *models.Certificate) error {
	res, err := db.Exec(`
		INSERT INTO certificates (
			serial_number, common_name, cert_type, certificate_pem, private_key_pem,
			p12_password, client_id, issued_at, expires_at, is_revoked, revoked_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(serial_number) DO UPDATE SET
			common_name = excluded.common_name,
			certificate_pem = excluded.certificate_pem,
			private_key_pem = COALESCE(excluded.private_key_pem, certificates.private_key_pem),
			p12_password = excluded.p12_password,
			is_revoked = excluded.is_revoked,
			revoked_at = excluded.revoked_at
	`,
		c.SerialNumber, c.CommonName, c.CertType, c.CertificatePEM, c.PrivateKeyPEM,
		c.P12Password, c.ClientID, c.IssuedAt.UTC(), c.ExpiresAt.UTC(), c.IsRevoked, c.RevokedAt,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err == nil && id > 0 {
		c.ID = id
	}
	return nil
}

// GetCertificateBySerial retrieves a certificate by serial number.
func (db *DB) GetCertificateBySerial(serial string) (*models.Certificate, error) {
	row := db.QueryRow(`
		SELECT id, serial_number, common_name, cert_type, certificate_pem, private_key_pem,
		       p12_password, client_id, issued_at, expires_at, is_revoked, revoked_at
		FROM certificates WHERE serial_number = ?
	`, serial)
	return scanCertificate(row)
}

// GetActiveCACertificate retrieves the latest non-revoked root CA certificate.
func (db *DB) GetActiveCACertificate() (*models.Certificate, error) {
	row := db.QueryRow(`
		SELECT id, serial_number, common_name, cert_type, certificate_pem, private_key_pem,
		       p12_password, client_id, issued_at, expires_at, is_revoked, revoked_at
		FROM certificates
		WHERE cert_type = 'ca' AND is_revoked = 0
		ORDER BY id DESC LIMIT 1
	`)
	return scanCertificate(row)
}

// GetActiveServerCertificate retrieves the latest non-revoked server certificate for RADIUS TLS.
func (db *DB) GetActiveServerCertificate() (*models.Certificate, error) {
	row := db.QueryRow(`
		SELECT id, serial_number, common_name, cert_type, certificate_pem, private_key_pem,
		       p12_password, client_id, issued_at, expires_at, is_revoked, revoked_at
		FROM certificates
		WHERE cert_type = 'server' AND is_revoked = 0
		ORDER BY id DESC LIMIT 1
	`)
	return scanCertificate(row)
}

// ListCertificates returns all certificates, optionally filtered by type.
func (db *DB) ListCertificates(certType string) ([]models.Certificate, error) {
	query := `
		SELECT id, serial_number, common_name, cert_type, certificate_pem, private_key_pem,
		       p12_password, client_id, issued_at, expires_at, is_revoked, revoked_at
		FROM certificates
	`
	var rows *sql.Rows
	var err error

	if certType != "" {
		query += " WHERE cert_type = ? ORDER BY id DESC"
		rows, err = db.Query(query, certType)
	} else {
		query += " ORDER BY id DESC"
		rows, err = db.Query(query)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []models.Certificate
	for rows.Next() {
		var c models.Certificate
		var revAt sql.NullTime
		var privKey sql.NullString
		var p12Pass sql.NullString
		err := rows.Scan(
			&c.ID, &c.SerialNumber, &c.CommonName, &c.CertType, &c.CertificatePEM,
			&privKey, &p12Pass, &c.ClientID, &c.IssuedAt, &c.ExpiresAt, &c.IsRevoked, &revAt,
		)
		if err != nil {
			return nil, err
		}
		c.PrivateKeyPEM = privKey.String
		c.P12Password = p12Pass.String
		if revAt.Valid {
			c.RevokedAt = &revAt.Time
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// RevokeCertificate marks a certificate as revoked.
func (db *DB) RevokeCertificate(serial string) error {
	now := time.Now().UTC()
	_, err := db.Exec("UPDATE certificates SET is_revoked = 1, revoked_at = ? WHERE serial_number = ?", now, serial)
	return err
}

func scanCertificate(row *sql.Row) (*models.Certificate, error) {
	var c models.Certificate
	var revAt sql.NullTime
	var privKey sql.NullString
	var p12Pass sql.NullString

	err := row.Scan(
		&c.ID, &c.SerialNumber, &c.CommonName, &c.CertType, &c.CertificatePEM,
		&privKey, &p12Pass, &c.ClientID, &c.IssuedAt, &c.ExpiresAt, &c.IsRevoked, &revAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCertNotFound
		}
		return nil, err
	}
	c.PrivateKeyPEM = privKey.String
	c.P12Password = p12Pass.String
	if revAt.Valid {
		c.RevokedAt = &revAt.Time
	}
	return &c, nil
}

