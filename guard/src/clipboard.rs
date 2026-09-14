//! Native clipboard access. The whole point of this binary: no subprocess, no runtime,
//! and a change check that costs nothing so it can run often.

pub trait Clipboard {
    /// Cheap token that changes whenever the clipboard contents change.
    fn token(&mut self) -> u64;
    fn read_text(&mut self) -> String;
    fn write_text(&mut self, text: &str);
    /// Name of the app in front, for the alert text. "unknown" where not available.
    fn frontmost_app(&self) -> String {
        "unknown".into()
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::Clipboard;
    use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString, NSWorkspace};
    use objc2_foundation::NSString;

    pub struct Native;

    impl Native {
        pub fn open() -> Result<Self, String> {
            let mut n = Native;
            let _ = n.token();
            Ok(n)
        }
    }

    impl Clipboard for Native {
        fn token(&mut self) -> u64 {
            NSPasteboard::generalPasteboard().changeCount() as u64
        }
        fn read_text(&mut self) -> String {
            let pb = NSPasteboard::generalPasteboard();
            // The pasteboard type constant is a foreign static; reading it is the only unsafe part.
            unsafe { pb.stringForType(NSPasteboardTypeString) }.map(|s| s.to_string()).unwrap_or_default()
        }
        fn write_text(&mut self, text: &str) {
            let pb = NSPasteboard::generalPasteboard();
            pb.clearContents();
            unsafe { pb.setString_forType(&NSString::from_str(text), NSPasteboardTypeString) };
        }
        fn frontmost_app(&self) -> String {
            NSWorkspace::sharedWorkspace()
                .frontmostApplication()
                .and_then(|a| a.localizedName())
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unknown".into())
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::Clipboard;
    use windows_sys::Win32::Foundation::{GlobalFree, HANDLE};
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber, OpenClipboard, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    const CF_UNICODETEXT: u32 = 13;

    pub struct Native;

    impl Native {
        pub fn open() -> Result<Self, String> {
            Ok(Native)
        }
    }

    struct Open;
    impl Open {
        fn new() -> Option<Open> {
            for _ in 0..10 {
                if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
                    return Some(Open);
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            None
        }
    }
    impl Drop for Open {
        fn drop(&mut self) {
            unsafe { CloseClipboard() };
        }
    }

    impl Clipboard for Native {
        fn token(&mut self) -> u64 {
            unsafe { GetClipboardSequenceNumber() as u64 }
        }
        fn read_text(&mut self) -> String {
            let Some(_open) = Open::new() else { return String::new() };
            let h: HANDLE = unsafe { GetClipboardData(CF_UNICODETEXT) };
            if h.is_null() {
                return String::new();
            }
            let p = unsafe { GlobalLock(h) } as *const u16;
            if p.is_null() {
                return String::new();
            }
            let mut len = 0usize;
            while unsafe { *p.add(len) } != 0 && len < 4 * 1024 * 1024 {
                len += 1;
            }
            let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) });
            unsafe { GlobalUnlock(h) };
            s
        }
        fn write_text(&mut self, text: &str) {
            let Some(_open) = Open::new() else { return };
            let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            let bytes = wide.len() * 2;
            unsafe {
                let h = GlobalAlloc(GMEM_MOVEABLE, bytes);
                if h.is_null() {
                    return;
                }
                let p = GlobalLock(h) as *mut u16;
                if p.is_null() {
                    GlobalFree(h);
                    return;
                }
                std::ptr::copy_nonoverlapping(wide.as_ptr(), p, wide.len());
                GlobalUnlock(h);
                EmptyClipboard();
                if SetClipboardData(CF_UNICODETEXT, h).is_null() {
                    GlobalFree(h);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::Clipboard;
    use std::hash::{DefaultHasher, Hash, Hasher};

    pub struct Native {
        cb: arboard::Clipboard,
    }

    impl Native {
        pub fn open() -> Result<Self, String> {
            arboard::Clipboard::new().map(|cb| Native { cb }).map_err(|e| e.to_string())
        }
    }

    impl Clipboard for Native {
        /// X11 has no cheap change counter; hashing the text is still in-process and spawn-free.
        fn token(&mut self) -> u64 {
            let mut h = DefaultHasher::new();
            self.read_text().hash(&mut h);
            h.finish()
        }
        fn read_text(&mut self) -> String {
            self.cb.get_text().unwrap_or_default()
        }
        fn write_text(&mut self, text: &str) {
            let _ = self.cb.set_text(text.to_owned());
        }
    }
}

pub use imp::Native;
