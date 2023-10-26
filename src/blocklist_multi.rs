//! Multiple tags blocklist
//!
//! This blocklist is designed to work when you have a lot of different, potentially overlapping blocklists.
//! For example, you may have the website `foo.com` that is both in A and B blocklists, and as such you'd like the blocklist to return `["A", "B"]`.
//!
//! Building might be slower than using the other blocklist available here, though.
//!
//! ## Directory structure
//! The directory should have a number of subdirs, which in turn should have `domains` and `urls` files.
//! The easiest way of using this is to get the whole [UT1 Blacklists](https://dsi.ut-capitole.fr/blacklists/index_en.php) archive,
//! to decompress it and to point to the decompressed folder. **Be careful though, as some blocklists are also compressed (like `adult/domains.gz`)**
//!
//! ## Subdomain matching
//!
//! This blocklist also tries to match subdomains.
//!
//! For example, if `blogspot.com` is in a `blogs` blocklist, `foo.blogspot.com` will be matched and the detector will return `["blogs"]`.
//! Moreover, if `sportsblog.blogspot.com` is in a `sports` blocklist, `sportsblog.blogspot.com` will be matched and the detector will return `["blogs", "sport"]`.
/*!
    ```text
    ├── README
    ├── ads -> publicite
    ├── adult
    │   ├── domains
    │   ├── domains.24733
    │   ├── domains.9309
    │   ├── expressions
    │   ├── urls
    │   ├── usage
    │   └── very_restrictive_expression
    ├── aggressive -> agressif
    ├── agressif
    │   ├── domains
    │   ├── expressions
    │   ├── urls
    │   └── usage
    ├── arjel
    │   ├── domains
    │   └── usage
    ├── associations_religieuses
    │   ├── domains
    │   └── usage
    ```
*/
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use crate::error::Ut1Error;
use log::{debug, info};
use url::{Position, Url};

// TODO: replace owned strings by refs to a (static?) tag.
/// Domain and URL blocklist
#[derive(Clone)]
pub struct Blocklist {
    domains: HashMap<String, Vec<String>>,
    urls: HashMap<Url, Vec<String>>,
}

impl Blocklist {
    pub fn new(domains: HashMap<String, Vec<String>>, urls: HashMap<Url, Vec<String>>) -> Self {
        Self { domains, urls }
    }
    /// Try to build a [Url] from a string representing an URL.
    /// If it fails, tries again by adding https:// at the beginning.
    #[inline]
    fn normalize(url: &str) -> Result<Url, url::ParseError> {
        url.parse().or_else(|_| {
            let url: String = ["https://", url].iter().cloned().collect();
            url.parse::<Url>()
        })
    }

    /// Get a URL and only keep everything from [Position::BeforeScheme] and [Position::AfterPath].
    fn normalize_url(url: &str) -> Result<Url, Ut1Error> {
        let url = Self::normalize(url)?;
        let url = &url[Position::BeforeScheme..Position::AfterPath];
        Ok(Url::parse(url)?)
    }

    /// Get a domain and only keep its [Url::host_str].
    fn normalize_domain(url: &str) -> Result<String, Ut1Error> {
        // try to convert into Url. If it fails, try again by adding https:// at the beginning of the url
        let url = Self::normalize(url)?;
        if let Some(domain) = url.host_str() {
            Ok(domain.to_string())
        } else {
            Err(Ut1Error::NoHostname(url.to_string()))
        }
    }

    // TODO: Rather than failing silently,
    // collect normalization errors and log em
    /// Builds a blocklist from a given ut1 blocklist directory.
    ///
    /// The directory should have a number of subdirs, which in turn should have `domains` and `urls` files.
    /**
    ```text
    ├── README
    ├── ads -> publicite
    ├── adult
    │   ├── domains
    │   ├── domains.24733
    │   ├── domains.9309
    │   ├── expressions
    │   ├── urls
    │   ├── usage
    │   └── very_restrictive_expression
    ├── aggressive -> agressif
    ├── agressif
    │   ├── domains
    │   ├── expressions
    │   ├── urls
    │   └── usage
    ├── arjel
    │   ├── domains
    │   └── usage
    ├── associations_religieuses
    │   ├── domains
    │   └── usage
    ```
    */
    pub fn from_dir(dir: &Path) -> Result<Self, std::io::Error> {
        info!("Building list from {dir:?}");
        let mut domains: HashMap<_, Vec<_>> = HashMap::new();
        let mut urls: HashMap<_, Vec<_>> = HashMap::new();

        for blocklist_path in std::fs::read_dir(dir)? {
            let blocklist_path = blocklist_path?.path();
            let bl_name = blocklist_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            debug!("Reading lists for category {bl_name:?}");

            let domain_path = {
                let mut d = blocklist_path.clone();
                d.push("domains");
                d
            };

            let urls_path = {
                let mut d = blocklist_path.clone();
                d.push("urls");
                d
            };

            if domain_path.exists() {
                debug!("loading {:?}", bl_name);
                let r = File::open(&domain_path)?;

                let bl_domains = BufReader::new(r)
                    .lines()
                    .filter_map(Result::ok)
                    .filter_map(|url| Self::normalize_domain(&url).ok());

                for domain in bl_domains {
                    // insert a new vec with blocklist name in it,
                    // or push the name in the existing vec
                    domains
                        .entry(domain)
                        .and_modify(|v| v.push(bl_name.clone()))
                        .or_insert_with(|| vec![bl_name.clone()]);
                }
            }

            if urls_path.exists() {
                let r = File::open(&urls_path)?;

                let bl_urls = BufReader::new(r)
                    .lines()
                    .filter_map(Result::ok)
                    .filter_map(|url| Self::normalize_url(&url).ok());

                for url in bl_urls {
                    // insert a new vec with blocklist name in it,
                    // or push the name in the existing vec
                    urls.entry(url)
                        .and_modify(|v| v.push(bl_name.clone()))
                        .or_insert_with(|| vec![bl_name.clone()]);
                }
            }
        }

        Ok(Self { domains, urls })
    }

    /// iteratively removes subdomains until there's a match
    // TODO optim: we know max number of subdomains in blocklist,
    //             so we could skip more
    fn detect_subdomains(&self, domain: &str) -> Option<HashSet<&String>> {
        // keep domain as vector of chars since we'll rely heavily on indexing
        // we use bytes to be able to use from_utf8 without having to allocate
        // it should be safe because even if we have some non utf8 chars, . is utf8
        let chars = domain.as_bytes();

        // get char indexes of dots (in for example foo.bar.com)
        let mut sep_positions: Vec<usize> = chars
            .iter()
            .enumerate()
            .filter(|(_, c)| c == &&(b'.'))
            .map(|(idx, _)| idx)
            .collect();

        // remove last position (between domain and TLD)
        // so that we don't match on tld alone
        sep_positions.pop();

        // iterate over separator positions
        let categories: HashSet<&String> = sep_positions
            .into_iter()
            .filter_map(|pos| {
                // string to test is 1 char after the subdomain delimiter unil the end
                // ignore if we can't build a string slice
                if let Ok(to_test) = std::str::from_utf8(&chars[pos + 1..]) {
                    if let Some(categories) = self.domains.get(to_test) {
                        // return categories if there's a match
                        return Some(categories);
                    }

                    return None;
                }
                None
            })
            // flatten nested vectors
            .flatten()
            .collect();

        if categories.is_empty() {
            None
        } else {
            Some(categories)
        }
    }

    /// checks if a given URL is present.
    /// If a given URL is present both in domain and urls, merges the tags.
    /// The returning hashset cannot be empty.
    pub fn detect(&self, url: &str) -> Option<HashSet<&String>> {
        let mut detections = HashSet::new();

        if let Ok(domain) = Self::normalize_domain(url) {
            // try with full domain
            let domain_tags = self.domains.get(&domain);
            if let Some(domain_tags) = domain_tags {
                detections.extend(domain_tags.iter());
            }
            // try with subdomains
            if let Some(domain_tags) = self.detect_subdomains(&domain) {
                detections.extend(&domain_tags);
            }
        }

        if let Ok(url) = Self::normalize_url(url) {
            let url_tags = self.urls.get(&url);
            if let Some(url_tags) = url_tags {
                detections.extend(url_tags.iter());
            }
        }

        if detections.is_empty() {
            None
        } else {
            Some(detections)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        ops::Deref,
        path::Path,
    };

    use url::Url;

    use super::Blocklist;

    // long test
    #[test]
    #[ignore]
    fn simple() {
        let b = Blocklist::from_dir(Path::new("blocklist/")).unwrap();
        assert_eq!(
            b.detect("https://abastrologie.com"),
            Some(["astrology".to_string()].iter().collect())
        );
    }

    #[test]
    fn subdomains() {
        let domains = vec![
            ("blogspot.com".to_string(), vec!["blog".to_string()]),
            (
                "adultblog.blogspot.com".to_string(),
                vec!["adult".to_string()],
            ),
        ]
        .into_iter()
        .collect();
        // let domains = vec![].into_iter().collect();
        let b = Blocklist::new(domains, HashMap::new());

        let test_urls: Vec<(_, Option<HashSet<_>>)> = vec![
            ("https://ujj.blogspot.com/things", Some(vec!["blog"])),
            (
                "https://ujj.foo.bar.blogspot.com/things/etc.txt",
                Some(vec!["blog"]),
            ),
            ("https://blogspot.com/index.html", Some(vec!["blog"])),
            ("https://logspot.com/index.html", None),
            (
                "https://adultblog.blogspot.com/index.html",
                Some(vec!["blog", "adult"]),
            ),
        ]
        .into_iter()
        .map(|(link, cat)| {
            (
                link,
                // cat.map(|x| x.into_iter().map(|y| String::from(y)).collect()),
                cat.map(|x| x.into_iter().collect()),
            )
        })
        .collect();

        for (test_url, categories) in test_urls {
            let results = b
                .detect(test_url)
                .map(|x| x.into_iter().map(|cat| cat.as_str()).collect());
            assert_eq!(results, categories);
        }
    }

    // TODO: Check if this test is actually useful?
    #[test]
    fn test_normalize_domain_add_https() {
        let domain = "abastrologie.com";
        let _normalized = Blocklist::normalize_domain(domain).unwrap();
    }

    // TODO: Check if this test is actually useful?
    #[test]
    fn test_normalize_url_add_https() {
        let url = "cri.univ-tlse1.fr/tools/test_filtrage/astrology/";
        let _normalized = Blocklist::normalize_url(url).unwrap();
    }
}
