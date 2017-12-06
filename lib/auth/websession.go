package auth

import (
	"crypto"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/tstranex/u2f"
)

type AuthenticateUserRequest struct {
	Username string                `json:"username"`
	Pass     *PassCreds            `json:"pass,omitempty"`
	U2F      *U2FSignResponseCreds `json:"u2f,omitempty"`
	OTP      *OTPCreds             `json:"otp,omitempty"`
}

func (a *AuthenticateUserRequest) CheckAndSetDefaults() error {
	if a.Username == "" {
		return trace.BadParameter("missing parameter 'username'")
	}
	if a.Pass == nil && a.U2F == nil && a.OTP == nil {
		return trace.BadParameter("at least one authentication method is required")
	}
	return nil
}

type PassCreds struct {
	Password []byte `json:"password"`
}

type U2FSignResponseCreds struct {
	SignResponse u2f.SignResponse `json:"sign_response"`
}

type OTPCreds struct {
	Password []byte `json:"password"`
	Token    string `json:"token"`
}

// AuthenticateUser authenticates user based on the request type
func (s *AuthServer) AuthenticateUser(req AuthenticateUserRequest) error {
	if err := req.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	authPreference, err := s.GetAuthPreference()
	if err != nil {
		return trace.Wrap(err)
	}

	switch {
	case req.Pass != nil:
		// authenticate using password only, make sure
		// that auth preference does not require second factor
		// otherwise users can bypass the second factor
		if authPreference.GetSecondFactor() != teleport.OFF {
			return trace.AccessDenied("missing second factor")
		}
		err := s.WithUserLock(req.Username, func() error {
			return s.CheckPasswordWOToken(req.Username, req.Pass.Password)
		})
		if err != nil {
			return trace.Wrap(err)
		}
	case req.U2F != nil:
		// authenticate using U2F - code checks challenge response
		// signed by U2F device of the user
		err := s.WithUserLock(req.Username, func() error {
			return s.CheckU2FSignResponse(req.Username, &req.U2F.SignResponse)
		})
		if err != nil {
			return trace.Wrap(err)
		}
	case req.OTP != nil:
		err := s.WithUserLock(req.Username, func() error {
			return s.CheckPassword(req.Username, req.OTP.Password, req.OTP.Token)
		})
		if err != nil {
			return trace.Wrap(err)
		}
	default:
		return trace.AccessDenied("unsupported authentication method")
	}
	return trace.AccessDenied("internal server error")
}

// AuthenticateWebUser authenticates web user, creates and  returns web session
// in case if authentication is successfull
func (s *AuthServer) AuthenticateWebUser(req AuthenticateUserRequest) (services.WebSession, error) {
	if err := s.AuthenticateUser(req); err != nil {
		return nil, trace.Wrap(err)
	}
	sess, err := s.NewWebSession(req.Username)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := s.UpsertWebSession(req.Username, sess); err != nil {
		return nil, trace.Wrap(err)
	}
	sess, err = services.GetWebSessionMarshaler().GenerateWebSession(sess)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return sess, nil
}

type AuthenticateSSHRequest struct {
	AuthenticateUserRequest
	// PublicKey is public key in ssh authorized_keys format
	PublicKey         []byte        `json:"public_key"`
	TTL               time.Duration `json:"ttl"`
	CompatibilityMode string        `json:"compatibility_mode"`
}

func (a *AuthenticateSSHRequest) CheckAndSetDefaults() error {
	if err := a.AuthenticateUserRequest.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if len(PublicKey) == 0 {
		return trace.BadParameter("missing parameter 'public_key'")
	}
	compatibility, err := utils.CheckCompatibilityFlag(a.CompatibilityMode)
	if err != nil {
		return trace.Wrap(err)
	}
	a.CompatibilityMode = compatibility
	return nil
}

// SSHLoginResponse is a response returned by web proxy, it preserves backwards compatibility
// on the wire, which is the primary reason for non-matching json tags
type SSHLoginResponse struct {
	// User contains a logged in user informationn
	Username string `json:"username"`
	// Cert is PEM encoded  signed certificate
	Cert []byte `json:"cert"`
	// TLSCertPEM is a PEM encoded TLS certificate signed by TLS certificate authority
	TLSCert []byte `json:"tls_cert"`
	// HostSigners is a list of signing host public keys trusted by proxy
	HostSigners []TrustedCerts `json:"host_signers"`
}

// TrustedCerts contains host certificates, it preserves backwards compatibility
// on the wire, which is the primary reason for non-matching json tags
type TrustedCerts struct {
	// ClusterName identifies teleport cluster name this authority serves,
	// for host authorities that means base hostname of all servers,
	// for user authorities that means organization name
	ClusterName string `json:"domain_name"`
	// HostCertificates is a list of SSH public keys that can be used to check
	// host certificate signatures
	HostCertificates [][]byte `json:"checking_keys"`
	// TLSCertificates  is a list of TLS certificates of the certificate authoritiy
	// of the authentication server
	TLSCertificates [][]byte `json:"tls_certs"`
}

func authoritiesToTrustedCerts(authorities []services.CertAuthority) []TrustedCerts {
	out := make([]TrustedCerts, len(authorities))
	for i, ca := range authorities {
		pairs := ca.GetTLSKeyPairs()
		certs := TrustedCerts{
			ClusterName:      ca.GetClusterName(),
			HostCertificates: ca.GetCheckingKeys(),
			TLSCertificates:  make([][]byte, len(pairs)),
		}
		for j, pair := range pairs {
			certs.TLSCertificates[j] = pair.Cert
		}
	}
	return out
}

// AuthenticateSSHUser authenticates web user, creates and  returns web session
// in case if authentication is successfull
func (s *AuthServer) AuthenticateSSHUser(req AuthenticateSSHRequest) (*SSHLoginResponse, error) {
	if err := s.AuthenticateUser(req.AuthenticateUserRequest); err != nil {
		return nil, trace.Wrap(err)
	}
	user, err := s.GetUser(req.Username)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roles, err := services.FetchRoles(user.GetRoles(), s, user.GetTraits())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	hostCertAuthorities, err := auth.GetCertAuthorities(services.HostCA, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certs, err := s.generateUserCert(certRequest{
		user:          user,
		roles:         roles,
		ttl:           req.TTL,
		publicKey:     req.PublicKey,
		compatibility: req.CompatibilityMode,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &SSHLoginResponse{
		Username:    req.Username,
		Cert:        certs.ssh,
		TLSCert:     certs.tls,
		HostSigners: authoritiesToTrustedCerts(hostCertAuthorities),
	}, nil
}
