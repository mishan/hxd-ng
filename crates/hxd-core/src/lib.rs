//! hxd-ng's domain layer.
//!
//! Everything in this crate is wire-format-free: no transaction types, no
//! chunk tags, no sockets. The session layer (hxd-session) translates between
//! the Hotline wire and these types; a future protocol frontend (the
//! Hotline-ng phase) talks to the same types. Keeping wire vocabulary out of
//! this crate's API is a roadmap commitment, not an accident — see
//! ROADMAP.md's architecture section.

pub mod access;
pub mod account;
pub mod avatar;
pub mod ban;
pub mod budget;
pub mod chat;
pub mod files;
pub mod history;
pub mod inbox;
pub mod instrument;
pub mod limits;
pub mod media;
pub mod moderation;
pub mod news;
pub mod notify;
pub mod push;
pub mod revoked;
pub mod roster;
pub mod system;
pub mod video;
pub mod voice;

pub use access::AccessBits;
pub use account::{
    Account, AccountDirectory, AuthBackend, AuthError, IdentityLink, LinkAuthority, LinkOutcome,
    Proof, UnlinkOutcome,
};
pub use avatar::{
    Avatar, AvatarId, AvatarImages, AvatarLimits, AvatarOwner, AvatarPolicy, AvatarRef,
    AvatarStore, MemoryAvatars,
};
pub use budget::{Over, QueueBudget, Share, QUEUE_BUDGET};
pub use chat::{ChatError, Flooded, KickBan, Kicked, MsgOutcome, SpamBan};
pub use files::{
    FileBody, FileEntry, FileError, FileFuture, FileInfo, FileKind, FilePath, FilePrincipal,
    FileSource,
};
pub use history::{
    ChatLog, HistoryPage, HistoryPolicy, HistoryQuery, LineFlags, LineId, LogLine, MediaMeta,
    MemoryLog, NewLine,
};
pub use inbox::{
    Delivery, InboxCounts, MemoryStore, MessageId, MessageStore, NewMessage, Pushed, Sent,
    StoreError, StoredMessage,
};
pub use limits::{
    AccountRefused, AddrSet, ChatLimits, ConnGate, ConnLimits, ConnPermit, ConnRefused,
    FloodLimits, LoginAttempt, LoginLimits, RateBucket, RateGate, RequestLimits, SharedPlace,
};
pub use media::{
    Canonical, CodecLimits, Fetched, Handle, HistoryAccess, MediaCodec, MediaConfig, MediaRecord,
    MediaRef, MediaReject, MediaType, Principal, UploadOutcome, UploadPart,
};
pub use moderation::{
    Act, ActKind, Actor, Filed, MemoryModeration, ModError, ModerationPolicy, ModerationStore,
    Outcome, PersonRef, Purged, Report, ReportFilter, ReportRequest, ReportTarget, Subject,
};
pub use news::{
    Article, ArticleId, ArticlePage, Attachment, AttachmentFetch, AttachmentPolicy, Author,
    AutoFollow, AutoSubscribe, BlobId, BlobStore, BodyRenderer, BodyType, Listed, MarkdownMode,
    MemoryNews, NewsError, NewsPolicy, NewsStore, NewsUsage, Node, NodeId, NodeKind, NodeTree,
    Notified, NotifyPolicy, NotifyReason, PostRequest, Reference, Rendered, StagedAttachment,
    SubScope, Subscriber, Subscription, TextLen, ThreadHead, ThreadPage, ThreadQuery,
};
pub use notify::{MessageNotice, NewsNotice, Notification, NotificationGateway};
pub use push::{Device, DeviceId, MemoryDevices, PushStore, Registered};
pub use revoked::Revocations;
pub use roster::{
    AttachInfo, Census, Core, Event, Events, IdentityTag, InboxPolicy, Lag, LoginPermit, Resume,
    SeqEvent, SessionStatus, Transport, Uid, UserDetails, UserInfo, LIVE_QUEUE_BYTES,
    LIVE_QUEUE_CAP, LOGINS_IN_FLIGHT, OUTBOX_BUFFER_CAP,
};
pub use system::SystemPolicy;
pub use video::{
    PublishRefusal, VideoConfig, VideoError, VideoKind, VideoLimits, VideoPublication, VideoStream,
};
pub use voice::{
    IceCandidate, MediaEvent, VoiceError, VoiceJoin, VoiceLimits, VoiceMedia, VoiceParticipant,
    DEFAULT_MAX_PER_ROOM,
};
