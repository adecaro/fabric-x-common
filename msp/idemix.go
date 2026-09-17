/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package msp

import (
	idemixmsp "github.com/IBM/idemix/msp"
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-common/api/msppb"
)

type idemixSigningIdentityWrapper struct {
	idemixmsp.SigningIdentity
}

func (i *idemixSigningIdentityWrapper) GetPublicVersion() Identity {
	return &idemixIdentityWrapper{Identity: i.SigningIdentity.GetPublicVersion()}
}

func (i *idemixSigningIdentityWrapper) GetIdentifier() *IdentityIdentifier {
	return i.GetPublicVersion().GetIdentifier()
}

func (i *idemixSigningIdentityWrapper) GetOrganizationalUnits() []*OUIdentifier {
	return i.GetPublicVersion().GetOrganizationalUnits()
}

func (*idemixSigningIdentityWrapper) SerializeWithIDOfCert() ([]byte, error) {
	return nil, errors.New("not applicable")
}

func (*idemixSigningIdentityWrapper) SerializeWithCert() ([]byte, error) {
	return nil, errors.New("not applicable")
}

func (*idemixSigningIdentityWrapper) GetCertificatePEM() ([]byte, error) {
	return nil, nil
}

type idemixIdentityWrapper struct {
	idemixmsp.Identity
}

func (i *idemixIdentityWrapper) GetIdentifier() *IdentityIdentifier {
	id := i.Identity.GetIdentifier()

	return &IdentityIdentifier{
		Mspid: id.Mspid,
		Id:    id.Id,
	}
}

func (*idemixIdentityWrapper) SerializeWithIDOfCert() ([]byte, error) {
	return nil, errors.New("not applicable")
}

func (*idemixIdentityWrapper) SerializeWithCert() ([]byte, error) {
	return nil, errors.New("not applicable")
}

// GetCertificatePEM returns the certificate in PEM format.
func (*idemixIdentityWrapper) GetCertificatePEM() ([]byte, error) {
	return nil, nil
}

func (i *idemixIdentityWrapper) GetOrganizationalUnits() []*OUIdentifier {
	ous := i.Identity.GetOrganizationalUnits()
	wous := []*OUIdentifier{}
	for _, ou := range ous {
		wous = append(wous, &OUIdentifier{
			CertifiersIdentifier:         ou.CertifiersIdentifier,
			OrganizationalUnitIdentifier: ou.OrganizationalUnitIdentifier,
		})
	}

	return wous
}

type idemixMSPWrapper struct {
	*idemixmsp.MSP
}

func (i *idemixMSPWrapper) deserializeIdentityInternal(serializedIdentity []byte) (Identity, error) {
	mspID, err := i.GetIdentifier()
	if err != nil {
		return nil, err
	}

	return i.DeserializeIdentity(&msppb.Identity{
		MspId:   mspID,
		Creator: &msppb.Identity_Certificate{Certificate: serializedIdentity},
	})
}

func (i *idemixMSPWrapper) DeserializeIdentity(identity *msppb.Identity) (Identity, error) { //nolint:ireturn
	si := msp.SerializedIdentity{Mspid: identity.MspId, IdBytes: identity.GetCertificate()}
	siBytes, err := proto.Marshal(&si)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal serialized identity")
	}
	id, err := i.MSP.DeserializeIdentity(siBytes)
	if err != nil {
		return nil, err
	}

	return &idemixIdentityWrapper{id}, nil
}

// GetKnownDeserializedIdentity returns a known identity matching the given IdentityIdentifier.
//
//nolint:ireturn //Identity is an interface.
func (*idemixMSPWrapper) GetKnownDeserializedIdentity(IdentityIdentifier) Identity {
	return nil
}

func (i *idemixMSPWrapper) IsWellFormed(identity *msppb.Identity) error {
	return i.MSP.IsWellFormed(&msp.SerializedIdentity{Mspid: identity.MspId, IdBytes: identity.GetCertificate()})
}

func (i *idemixMSPWrapper) GetVersion() MSPVersion {
	return MSPVersion(i.MSP.GetVersion())
}

func (i *idemixMSPWrapper) GetType() ProviderType {
	return ProviderType(i.MSP.GetType())
}

func (*idemixMSPWrapper) GetCertificatePEM() ([]byte, error) {
	return nil, nil
}

func (i *idemixMSPWrapper) GetDefaultSigningIdentity() (SigningIdentity, error) {
	id, err := i.MSP.GetDefaultSigningIdentity()
	if err != nil {
		return nil, err
	}

	return &idemixSigningIdentityWrapper{id}, nil
}

func (i *idemixMSPWrapper) Validate(id Identity) error {
	wrapper, ok := id.(*idemixIdentityWrapper)
	if !ok {
		return errors.New("identity is not idemix: type assertion failed")
	}

	return i.MSP.Validate(wrapper.Identity)
}

func (i *idemixMSPWrapper) SatisfiesPrincipal(id Identity, principal *msp.MSPPrincipal) error {
	wrapper, ok := id.(*idemixIdentityWrapper)
	if !ok {
		return errors.New("identity is not idemix: type assertion failed")
	}

	return i.MSP.SatisfiesPrincipal(wrapper.Identity, principal)
}
