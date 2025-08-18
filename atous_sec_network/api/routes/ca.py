"""Certificate Authority (CA) management API routes.

This module provides endpoints for:
- Certificate issuance and management
- Certificate revocation
- CA information and statistics
- Certificate lifecycle management
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Query
from pydantic import BaseModel, Field
from typing import Optional, Dict, List
from datetime import datetime, UTC

from ...security.ca_service import ProductionCAService, CertificatePolicy
from ...security.identity_service import IdentityService
from ...core.logging_config import get_logger

logger = get_logger('api.ca')

router = APIRouter(prefix="/v1/ca", tags=["ca"])

# Initialize services
ca_service = ProductionCAService()
identity_service = IdentityService()


# Pydantic models
class CertificateIssuanceRequest(BaseModel):
    csr_pem: str = Field(..., description="Certificate Signing Request in PEM format")
    common_name: Optional[str] = Field(None, description="Override common name for certificate")
    validity_days: Optional[int] = Field(None, ge=1, le=365, description="Certificate validity in days")


class CertificateIssuanceResponse(BaseModel):
    certificate_pem: str
    ca_chain_pem: str
    serial_number: int
    common_name: str
    issued_at: str
    expires_at: str


class CertificateRevocationRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=200, description="Reason for revocation")


class CertificateStatusResponse(BaseModel):
    serial_number: int
    common_name: str
    status: str
    issued_at: str
    expires_at: str
    revocation_reason: Optional[str] = None
    revoked_at: Optional[str] = None


class CAInfoResponse(BaseModel):
    ca_subject: str
    ca_issuer: str
    ca_valid_from: str
    ca_valid_until: str
    total_certificates: int
    status_counts: Dict[str, int]
    policy: Dict


class CertificateListResponse(BaseModel):
    certificates: List[CertificateStatusResponse]
    total: int
    limit: int


# Dependency functions
def get_identity_service() -> IdentityService:
    """Get identity service instance."""
    return identity_service


def require_admin_access(request: Request,
                        identity_service: IdentityService = Depends(get_identity_service)) -> bool:
    """Require admin access for CA operations."""
    authorization = request.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization required")
    
    session_token = authorization[7:]  # Remove "Bearer " prefix
    user_info = identity_service.validate_session(session_token)
    
    if not user_info or user_info["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return True


# Certificate management endpoints
@router.post("/certificates", response_model=CertificateIssuanceResponse)
async def issue_certificate(request: CertificateIssuanceRequest,
                          admin_access: bool = Depends(require_admin_access)):
    """Issue a new certificate from CSR."""
    try:
        # Issue certificate
        cert_pem, ca_pem, serial_number = ca_service.issue_certificate(
            csr_pem=request.csr_pem,
            common_name=request.common_name
        )
        
        # Get certificate details
        cert_info = ca_service.get_certificate_status(serial_number)
        if not cert_info:
            raise HTTPException(status_code=500, detail="Failed to retrieve certificate info")
        
        logger.info(f"Issued certificate {serial_number} for {cert_info['common_name']}")
        
        return CertificateIssuanceResponse(
            certificate_pem=cert_pem,
            ca_chain_pem=ca_pem,
            serial_number=serial_number,
            common_name=cert_info["common_name"],
            issued_at=cert_info["issued_at"],
            expires_at=cert_info["expires_at"]
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Certificate issuance failed: {e}")
        raise HTTPException(status_code=500, detail="Certificate issuance failed")


@router.post("/certificates/{serial_number}/revoke")
async def revoke_certificate(serial_number: int,
                           request: CertificateRevocationRequest,
                           admin_access: bool = Depends(require_admin_access)):
    """Revoke a certificate."""
    try:
        success = ca_service.revoke_certificate(
            serial_number=serial_number,
            reason=request.reason
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Certificate not found or already revoked")
        
        logger.info(f"Certificate {serial_number} revoked: {request.reason}")
        return {"message": "Certificate revoked successfully", "serial_number": serial_number}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Certificate revocation failed: {e}")
        raise HTTPException(status_code=500, detail="Certificate revocation failed")


@router.get("/certificates/{serial_number}", response_model=CertificateStatusResponse)
async def get_certificate_status(serial_number: int,
                               admin_access: bool = Depends(require_admin_access)):
    """Get certificate status and details."""
    try:
        cert_info = ca_service.get_certificate_status(serial_number)
        if not cert_info:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        return CertificateStatusResponse(**cert_info)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get certificate status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get certificate status")


@router.get("/certificates", response_model=CertificateListResponse)
async def list_certificates(status: Optional[str] = None,
                          limit: int = Query(default=100, ge=1, le=1000),
                          admin_access: bool = Depends(require_admin_access)):
    """List certificates with optional filtering."""
    try:
        certificates = ca_service.list_certificates(status=status, limit=limit)
        
        # Convert to response format
        cert_responses = []
        for cert in certificates:
            cert_responses.append(CertificateStatusResponse(**cert))
        
        return CertificateListResponse(
            certificates=cert_responses,
            total=len(cert_responses),
            limit=limit
        )
    except Exception as e:
        logger.error(f"Failed to list certificates: {e}")
        raise HTTPException(status_code=500, detail="Failed to list certificates")


@router.get("/info", response_model=CAInfoResponse)
async def get_ca_info(admin_access: bool = Depends(require_admin_access)):
    """Get CA information and statistics."""
    try:
        ca_info = ca_service.get_ca_info()
        
        if "error" in ca_info:
            raise HTTPException(status_code=500, detail=ca_info["error"])
        
        return CAInfoResponse(**ca_info)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get CA info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get CA info")


@router.get("/policy")
async def get_ca_policy(admin_access: bool = Depends(require_admin_access)):
    """Get current CA policy configuration."""
    try:
        policy = ca_service.policy
        return {
            "key_size": policy.key_size,
            "key_type": policy.key_type,
            "validity_days": policy.validity_days,
            "max_path_length": policy.max_path_length,
            "allowed_key_usages": policy.allowed_key_usages,
            "allowed_extended_key_usages": policy.allowed_extended_key_usages
        }
    except Exception as e:
        logger.error(f"Failed to get CA policy: {e}")
        raise HTTPException(status_code=500, detail="Failed to get CA policy")


@router.put("/policy")
async def update_ca_policy(policy_update: Dict,
                          admin_access: bool = Depends(require_admin_access)):
    """Update CA policy configuration (admin only)."""
    try:
        # Validate policy parameters
        if "key_size" in policy_update and policy_update["key_size"] not in [2048, 4096]:
            raise HTTPException(status_code=400, detail="Key size must be 2048 or 4096")
        
        if "validity_days" in policy_update and not (1 <= policy_update["validity_days"] <= 365):
            raise HTTPException(status_code=400, detail="Validity days must be between 1 and 365")
        
        # Create new policy
        new_policy = CertificatePolicy(
            key_size=policy_update.get("key_size", ca_service.policy.key_size),
            key_type=policy_update.get("key_type", ca_service.policy.key_type),
            validity_days=policy_update.get("validity_days", ca_service.policy.validity_days),
            max_path_length=policy_update.get("max_path_length", ca_service.policy.max_path_length)
        )
        
        # Update service policy
        ca_service.policy = new_policy
        
        logger.info("CA policy updated")
        return {"message": "CA policy updated successfully", "policy": {
            "key_size": new_policy.key_size,
            "key_type": new_policy.key_type,
            "validity_days": new_policy.validity_days,
            "max_path_length": new_policy.max_path_length
        }}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update CA policy: {e}")
        raise HTTPException(status_code=500, detail="Failed to update CA policy")


# Health check endpoint
@router.get("/health")
async def ca_health():
    """Check CA service health."""
    try:
        # Simple health check - try to get CA info
        ca_info = ca_service.get_ca_info()
        
        if "error" in ca_info:
            return {
                "status": "unhealthy",
                "error": ca_info["error"],
                "timestamp": datetime.now(UTC).isoformat(),
                "service": "ca"
            }
        
        return {
            "status": "healthy",
            "timestamp": datetime.now(UTC).isoformat(),
            "service": "ca",
            "total_certificates": ca_info.get("total_certificates", 0)
        }
    except Exception as e:
        logger.error(f"CA service health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(UTC).isoformat(),
            "service": "ca"
        }


# Utility endpoints
@router.post("/validate-csr")
async def validate_csr(csr_pem: str):
    """Validate a Certificate Signing Request."""
    try:
        from cryptography import x509
        
        # Parse CSR
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        
        # Extract information
        subject = csr.subject
        public_key = csr.public_key()
        
        # Get common name
        common_name = None
        try:
            cn_attr = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]
            common_name = cn_attr.value
        except Exception:
            pass
        
        # Validate key
        key_info = {
            "type": type(public_key).__name__,
            "size": getattr(public_key, 'key_size', None)
        }
        
        return {
            "valid": True,
            "common_name": common_name,
            "subject": str(subject),
            "public_key": key_info,
            "signature_algorithm": str(csr.signature_algorithm_oid)
        }
    except Exception as e:
        return {
            "valid": False,
            "error": str(e)
        }


@router.get("/download/ca-certificate")
async def download_ca_certificate():
    """Download CA certificate in PEM format."""
    try:
        # Get CA certificate from service
        ca_cert = ca_service._ca_cert
        if not ca_cert:
            raise HTTPException(status_code=500, detail="CA certificate not available")
        
        from fastapi.responses import Response
        from cryptography.hazmat.primitives import serialization
        
        cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        
        return Response(
            content=cert_pem,
            media_type="application/x-pem-file",
            headers={
                "Content-Disposition": "attachment; filename=ca_certificate.pem"
            }
        )
    except Exception as e:
        logger.error(f"Failed to download CA certificate: {e}")
        raise HTTPException(status_code=500, detail="Failed to download CA certificate")
