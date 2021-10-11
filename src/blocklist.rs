/*! Blocklists.

Contains basic filtering code and constructors.

Filtering methods can be used on [Url]s.

!*/
use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use url::{Position, Url};

use crate::error::Ut1Error as Error;

/// Blocklist instantiation/detection.
///
///  A Blocklist contains a `kind` which corresponds to a folder name,
///  and url/domain filters:
///
///  - *filter_url* will act on whole URLS
///  - *filter_domain* will only check if the provided url's domain is present in the blocklist.
///
pub struct Blocklist<'a> {
    kind: &'a str,
    domains: HashSet<String>,
    urls: HashSet<String>,
}

impl<'a> Blocklist<'a> {
    /// create a blocklist from specified kind and folder.
    ///
    /// It will look for  `path/of/the/folder/kind`.
    pub fn with_folder(kind: &'a str, folder: &Path) -> Result<Self, Error> {
        let mut file_path = PathBuf::from(folder);

        if !file_path.is_dir() {
            return Err(Error::NotADirectory(file_path));
        }

        file_path.push(kind);

        let mut domains = file_path.clone();
        domains.push("domains");
        let mut urls = file_path.clone();
        urls.push("urls");

        let domains =
            File::open(domains).map_err(|_| Error::BlocklistNotFound(file_path.clone()))?;
        let urls = File::open(urls).map_err(|_| Error::BlocklistNotFound(file_path.clone()))?;

        let domains = BufReader::new(domains)
            .lines()
            .filter_map(Result::ok)
            .collect();

        let urls = BufReader::new(urls)
            .lines()
            .filter_map(Result::ok)
            .collect();

        Ok(Self {
            kind,
            domains,
            urls,
        })
    }

    /// Get a reference to the blocklist's domains.
    pub fn domains(&self) -> &HashSet<String> {
        &self.domains
    }

    /// returns `true` if domain of the provided url is in the domains list,
    /// `false` if not, or if there's no domain in the url.
    ///
    pub fn detect_domain(&self, url: &Url) -> bool {
        if let Some(domain) = url.domain() {
            self.domains.contains(domain)
        } else {
            false
        }
    }

    /// returns `true` if url is in the domains list.
    ///
    /// `url` is stripped of everything before host and everything after path.
    /// `https://foo.bar/baz?quux=true` becomes `foo.bar/baz`.
    pub fn detect_url(&self, url: &Url) -> bool {
        let url = &url[Position::BeforeHost..Position::AfterPath];

        self.urls.contains(url)
    }

    /// Get a reference to the blocklist's kind.
    pub fn kind(&self) -> &&'a str {
        &self.kind
    }
}

impl<'a> Default for Blocklist<'a> {
    /// Looks by default for "./ut1-blacklists/blacklists", getting the "adult" one.
    fn default() -> Self {
        let default_folder = PathBuf::from("./ut1-blacklists/blacklists/");
        Self::with_folder("adult", &default_folder)
            .unwrap_or_else(|_| panic!("{:?} not found", default_folder))
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs::File, io::Write, str::FromStr};

    use url::Url;

    use super::Blocklist;
    use tempfile;

    fn get_test_blocklist() -> Result<Blocklist<'static>, Box<dyn Error>> {
        let bl_folder = tempfile::tempdir()?;
        let bl_adult_folder = bl_folder.path().join("adult");
        std::fs::create_dir(&bl_adult_folder)?;

        let bl_domains_file = bl_adult_folder.clone().join("domains");
        let mut bl_domains_file = File::create(bl_domains_file)?;
        bl_domains_file.write_all("foo.bar".as_bytes())?;

        let bl_urls_file = bl_adult_folder.clone().join("urls");
        let mut bl_urls_file = File::create(bl_urls_file)?;
        bl_urls_file.write_all("foo.bar/baz".as_bytes())?;

        let bl = Blocklist::with_folder("adult", bl_folder.path())?;
        Ok(bl)
    }

    #[test]
    fn domain_contains() {
        let url = Url::from_str("https://foo.bar").unwrap();
        let bl = get_test_blocklist().unwrap();

        assert!(bl.detect_domain(&url));
    }

    #[test]
    fn domain_not_contains() {
        let url = Url::from_str("https://good.domain").unwrap();
        let bl = get_test_blocklist().unwrap();

        assert!(!bl.detect_domain(&url));
    }

    #[test]
    fn url_contains() {
        let url = Url::from_str("https://foo.bar/baz").unwrap();
        let bl = get_test_blocklist().unwrap();

        assert!(bl.detect_url(&url));
    }

    #[test]
    fn url_not_contains() {
        let url = Url::from_str("https://foo.bar/baz/quux").unwrap();
        let bl = get_test_blocklist().unwrap();

        assert!(!bl.detect_url(&url));
    }
}
