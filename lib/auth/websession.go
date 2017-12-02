package auth

import (
	"github.com/gravitational/teleport"

	"github.com/gravitational/teleport/lib/services"

	"github.com/gravitational/trace"
	"github.com/tstranex/u2f"
)

type AuthenticateWebUserRequest struct {
	Username string                `json:"username"`
	Pass     *PassCreds            `json:"pass,omitempty"`
	U2F      *U2FSignResponseCreds `json:"u2f,omitempty"`
	OTP      *OTPCreds             `json:"otp,omitempty"`
}

func (a *AuthenticateWebUserRequest) CheckAndSetDefaults() error {
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

// AuthenticateWebUser authenticates web user, creates and  returns web session
// in case if authentication is successfull
func (s *AuthServer) AuthenticateWebUser(req AuthenticateWebUserRequest) (services.WebSession, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	authPreference, err := s.GetAuthPreference()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch {
	case req.Pass != nil:
		// authenticate using password only, make sure
		// that auth preference does not require second factor
		// otherwise users can bypass the second factor
		if authPreference.GetSecondFactor() != teleport.OFF {
			return nil, trace.AccessDenied("missing second factor")
		}
		err := s.WithUserLock(req.Username, func() error {
			return s.CheckPasswordWOToken(req.Username, req.Pass.Password)
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
	case req.U2F != nil:
		// authenticate using U2F - code checks challenge response
		// signed by U2F device of the user
		err := s.WithUserLock(req.Username, func() error {
			return s.CheckU2FSignResponse(req.Username, &req.U2F.SignResponse)
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
	case req.OTP != nil:
		err := s.WithUserLock(req.Username, func() error {
			return s.CheckPassword(req.Username, req.OTP.Password, req.OTP.Token)
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
	default:
		return nil, trace.AccessDenied("unsupported authentication method")
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
