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
pub mod chat;
pub mod files;
pub mod history;
pub mod inbox;
pub mod media;
pub mod news;
pub mod notify;
pub mod roster;
pub mod video;
pub mod voice;

pub use access::AccessBits;
pub use account::{
    Account, AccountDirectory, AuthBackend, AuthError, IdentityLink, LinkAuthority, LinkOutcome,
    Proof, UnlinkOutcome,
};
pub use chat::{ChatError, MsgOutcome};
pub use files::{
    FileBody, FileEntry, FileError, FileFuture, FileInfo, FileKind, FilePath, FilePrincipal,
    FileSource,
};
pub use history::{
    ChatLog, HistoryPage, HistoryPolicy, HistoryQuery, LineFlags, LineId, LogLine, MediaMeta,
    MemoryLog, NewLine,
};
pub use inbox::{
    Delivery, InboxCounts, MemoryStore, MessageId, MessageStore, NewMessage, Pushed, StoreError,
    StoredMessage,
};
pub use media::{
    Canonical, CodecLimits, Fetched, Handle, HistoryAccess, MediaCodec, MediaConfig, MediaRef,
    MediaReject, MediaType, Principal, UploadOutcome, UploadPart,
};
pub use news::{
    Article, ArticleId, ArticlePage, Author, AutoFollow, AutoSubscribe, BodyRenderer, BodyType,
    MarkdownMode, MemoryNews, NewsError, NewsPolicy, NewsStore, Node, NodeId, NodeKind, NodeTree,
    Notified, NotifyPolicy, NotifyReason, PostRequest, Reference, Rendered, SubScope, Subscriber,
    Subscription, ThreadHead, ThreadPage, ThreadQuery,
};
pub use notify::{MessageNotice, NewsNotice, Notification, NotificationGateway};
pub use roster::{
    AttachInfo, Core, Event, IdentityTag, InboxPolicy, Resume, SeqEvent, SessionStatus, Transport,
    Uid, UserDetails, UserInfo, OUTBOX_BUFFER_CAP,
};
pub use video::{VideoConfig, VideoError, VideoKind, VideoLimits, VideoPublication, VideoStream};
pub use voice::{
    IceCandidate, MediaEvent, VoiceError, VoiceJoin, VoiceMedia, VoiceParticipant,
    DEFAULT_MAX_PER_ROOM,
};
