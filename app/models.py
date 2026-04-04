"""
SQLAlchemy ORM models.
All models live in the 'iplist' schema inside the 'mikrotik' database.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    Text,
    event,
)
from sqlalchemy.orm import relationship

from app.database import Base

SCHEMA = "iplist"

# ---------------------------------------------------------------------------
# Helper: every UPDATE must bump updateDate via a PostgreSQL trigger (created
# in the Alembic migration).  The column is defined here so the ORM maps it.
# ---------------------------------------------------------------------------


def _utcnow():
    return datetime.now(timezone.utc)


class _StandardMixin:
    """Common columns every table shares."""

    id = Column(BigInteger, primary_key=True, autoincrement=True, nullable=False)
    createDate = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updateDate = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)
    flagInactive = Column(SmallInteger, nullable=False, default=0)


# ---------------------------------------------------------------------------
# iplists
# ---------------------------------------------------------------------------


class IpList(_StandardMixin, Base):
    __tablename__ = "iplists"
    __table_args__ = (
        Index("ix_iplists_flagInactive", "flagInactive"),
        {"schema": SCHEMA},
    )

    url = Column(Text, nullable=False)
    flagBlacklist = Column(SmallInteger, nullable=False, default=0)
    description = Column(Text, nullable=True)
    comment = Column(Text, nullable=True)
    lastSync = Column(DateTime(timezone=True), nullable=True)
    fetchFrequencyHours = Column(Integer, nullable=False, default=0)

    ipAddresses = relationship(
        "IpAddress", back_populates="ipList", cascade="all, delete-orphan"
    )
    fetchJobs = relationship("FetchJob", back_populates="ipList", cascade="all, delete-orphan")
    fetchErrors = relationship("FetchError", back_populates="ipList", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# ipAddresses
# ---------------------------------------------------------------------------


class IpAddress(_StandardMixin, Base):
    __tablename__ = "ipAddresses"
    __table_args__ = (
        Index("ix_ipAddresses_flagInactive", "flagInactive"),
        Index("ix_ipAddresses_iplistsId_flagInactive", "iplistsId", "flagInactive"),
        {"schema": SCHEMA},
    )

    ipAddress = Column(Text, nullable=False)
    iplistsId = Column(
        BigInteger, ForeignKey(f"{SCHEMA}.iplists.id", ondelete="CASCADE"), nullable=False
    )

    ipList = relationship("IpList", back_populates="ipAddresses")


# ---------------------------------------------------------------------------
# firewallTypes
# ---------------------------------------------------------------------------


class FirewallType(_StandardMixin, Base):
    __tablename__ = "firewallTypes"
    __table_args__ = (
        Index("ix_firewallTypes_flagInactive", "flagInactive"),
        {"schema": SCHEMA},
    )

    firewallTypeDescription = Column(Text, nullable=False)

    firewalls = relationship("Firewall", back_populates="firewallType")


# ---------------------------------------------------------------------------
# firewalls
# ---------------------------------------------------------------------------


class Firewall(_StandardMixin, Base):
    __tablename__ = "firewalls"
    __table_args__ = (
        Index("ix_firewalls_flagInactive", "flagInactive"),
        {"schema": SCHEMA},
    )

    firewallAddress = Column(Text, nullable=False)
    firewallPort = Column(Integer, nullable=False)
    firewallUser = Column(Text, nullable=False)
    firewallSecret = Column(Text, nullable=False)  # AES-256 encrypted at rest
    firewallTypeId = Column(
        BigInteger, ForeignKey(f"{SCHEMA}.firewallTypes.id"), nullable=False
    )
    applyFrequencyHours = Column(Integer, nullable=False, default=0)

    firewallType = relationship("FirewallType", back_populates="firewalls")
    applyHistory = relationship(
        "ApplyHistory", back_populates="firewall", cascade="all, delete-orphan"
    )


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------


class Configuration(_StandardMixin, Base):
    __tablename__ = "configuration"
    __table_args__ = (
        Index("ix_configuration_flagInactive", "flagInactive"),
        {"schema": SCHEMA},
    )

    configurationItem = Column(Text, nullable=False)
    configurationHelp = Column(Text, nullable=True)
    configurationItemValue = Column(Text, nullable=True)


# ---------------------------------------------------------------------------
# fetchJobs
# ---------------------------------------------------------------------------


class FetchJob(_StandardMixin, Base):
    __tablename__ = "fetchJobs"
    __table_args__ = (
        Index("ix_fetchJobs_flagInactive", "flagInactive"),
        Index("ix_fetchJobs_iplistsId_status", "iplistsId", "status"),
        {"schema": SCHEMA},
    )

    iplistsId = Column(
        BigInteger, ForeignKey(f"{SCHEMA}.iplists.id", ondelete="CASCADE"), nullable=False
    )
    status = Column(Text, nullable=False, default="pending")
    startedAt = Column(DateTime(timezone=True), nullable=True)
    completedAt = Column(DateTime(timezone=True), nullable=True)
    errorMessage = Column(Text, nullable=True)
    entriesParsed = Column(Integer, nullable=True)
    entriesLoaded = Column(Integer, nullable=True)

    ipList = relationship("IpList", back_populates="fetchJobs")


# ---------------------------------------------------------------------------
# fetchErrors
# ---------------------------------------------------------------------------


class FetchError(_StandardMixin, Base):
    __tablename__ = "fetchErrors"
    __table_args__ = (
        Index("ix_fetchErrors_flagInactive", "flagInactive"),
        Index("ix_fetchErrors_iplistsId_occurredAt", "iplistsId", "occurredAt"),
        {"schema": SCHEMA},
    )

    iplistsId = Column(
        BigInteger, ForeignKey(f"{SCHEMA}.iplists.id", ondelete="CASCADE"), nullable=False
    )
    attempt = Column(Integer, nullable=False)
    errorMessage = Column(Text, nullable=False)
    occurredAt = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    ipList = relationship("IpList", back_populates="fetchErrors")


# ---------------------------------------------------------------------------
# applyHistory
# ---------------------------------------------------------------------------


class ApplyHistory(_StandardMixin, Base):
    __tablename__ = "applyHistory"
    __table_args__ = (
        Index("ix_applyHistory_flagInactive", "flagInactive"),
        Index("ix_applyHistory_firewallsId_startedAt", "firewallsId", "startedAt"),
        {"schema": SCHEMA},
    )

    firewallsId = Column(
        BigInteger, ForeignKey(f"{SCHEMA}.firewalls.id", ondelete="CASCADE"), nullable=False
    )
    status = Column(Text, nullable=False, default="pending")
    startedAt = Column(DateTime(timezone=True), nullable=True)
    completedAt = Column(DateTime(timezone=True), nullable=True)
    whitelistHash = Column(Text, nullable=True)
    blacklistHash = Column(Text, nullable=True)
    whitelistCount = Column(Integer, nullable=True)
    blacklistCount = Column(Integer, nullable=True)
    errorMessage = Column(Text, nullable=True)

    firewall = relationship("Firewall", back_populates="applyHistory")
