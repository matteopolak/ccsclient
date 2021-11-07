#[macro_use]
extern crate lazy_static;

use std::{
	fs::{self, File},
	io::{BufRead, BufReader},
	path::{Path, PathBuf},
	process::{Command, Stdio},
	thread, time,
};

use hex;
use regex::Regex;
use reqwest;
use sha2::{Digest, Sha512};
use similar::{ChangeTag, TextDiff};

#[cfg(target_os = "linux")]
static MACHINE: &str = "ubuntu";

#[cfg(target_os = "windows")]
static MACHINE: &str = "win10";

#[cfg(target_os = "windows")]
lazy_static! {
	static ref REPLACER: Regex = Regex::new("\\s*=\\s*").unwrap();
	static ref BASE: PathBuf = Path::new("C:\\CyberPatriot").to_path_buf();
	static ref BIN: PathBuf = BASE.join("CCSCheck.exe").to_path_buf();
	static ref MACHINE_UID: String = machine_uid::get().unwrap();
	static ref TEAM_ID: String = std::env::var("TEAM_ID").unwrap_or("0123-0123-0123".to_string());
}

#[cfg(target_os = "linux")]
lazy_static! {
	static ref REPLACER: Regex = Regex::new("\\s*=\\s*").unwrap();
	static ref BASE: PathBuf = Path::new("/opt/CyberPatriot").to_path_buf();
	static ref BIN: PathBuf = BASE.join("CCSCheck").to_path_buf();
	static ref MACHINE_UID: String = machine_uid::get().unwrap();
	static ref TEAM_ID: String = std::env::var("TEAM_ID").unwrap_or("0123-0123-0123".to_string());
}

fn submit_answer(answer: &str, removed: bool) {
	Command::new(BIN.as_os_str())
		.arg(answer)
		.arg(if removed { "1" } else { "0" })
		.env("TEAM_ID", TEAM_ID.as_str())
		.spawn()
		.ok();
}

fn format_answer(answer: &str) -> String {
	let replaced = REPLACER.replace_all(answer.trim(), "=");
	let lower = replaced.to_lowercase();
	let mut data = lower.split_whitespace().into_iter().collect::<Vec<&str>>();

	data.sort();

	data.join(" ")
}

fn check_file(path: &Path) {
	let path_str = path.to_str().unwrap();
	let mut hasher = Sha512::new();

	hasher.update(path_str);

	let hash = hex::encode(hasher.finalize_reset());
	let stored_path = BASE.join("diffs").join(hash.as_str());

	let stored_exists = stored_path.exists();
	let new_exists = path.exists();

	let new = match new_exists && path.is_file() {
		true => fs::read_to_string(&path).unwrap_or("".to_string()),
		false => "".to_string(),
	};

	let old = match stored_exists && stored_path.is_file() {
		true => fs::read_to_string(&stored_path).unwrap_or("".to_string()),
		false => "".to_string(),
	};

	check_diff(&old, &new, path_str);

	if !new_exists {
		fs::remove_file(stored_path).ok();

		if stored_exists {
			submit_answer(path_str, true);
		}
	} else {
		fs::write(stored_path, new).unwrap();

		if !stored_exists {
			submit_answer(path_str, false);
		}
	}
}

fn check_diff(old: &String, new: &String, path_str: &str) {
	let diff = TextDiff::from_lines(old, new);

	for change in diff.iter_all_changes() {
		let removed = match change.tag() {
			ChangeTag::Delete => true,
			ChangeTag::Insert => false,
			ChangeTag::Equal => continue,
		};

		let line = change.as_str().unwrap();

		if line.is_empty() {
			continue;
		}

		//#[cfg(target_os = "linux")]
		if path_str == "/etc/passwd" {
			if let Some(username) = line.split(':').next() {
				submit_answer(&format!("{}{}", username, path_str), removed);
			}
		} else if path_str == "/etc/group" {
			let mut split = line.split(':');

			if let Some(group) = split.next() {
				if let Some(users) = split.nth(2) {
					for user in users.split(',') {
						submit_answer(&format!("{}:{}{}", group, user, path_str), removed);
					}
				}
			}
		}

		submit_answer(
			&format!("{}{}", format_answer(line), path_str),
			removed
		);
	}
}

fn check_processes() {
	let path = BASE.join("diffs").join("processes");

	#[cfg(target_os = "linux")]
	let output = Command::new("/bin/bash")
		.arg("-c")
		.arg("/bin/ps -axo cmd | /bin/grep -Po \"^[^ ]+\" | /bin/uniq | /bin/tail -n +2 | /bin/head -n -5")
		.stdout(Stdio::piped())
		.output()
		.unwrap();

	#[cfg(target_os = "windows")]
	let output = Command::new("powershell")
		.arg("Get-Process | Get-Unique | Select-Object -Property ProcessName")
		.stdout(Stdio::piped())
		.output()
		.unwrap();

	let new = String::from_utf8(output.stdout).unwrap();
	let old = fs::read_to_string(&path).unwrap();

	check_diff(&old, &new, "");

	fs::write(path, new).unwrap();
}

#[cfg(target_os = "linux")]
fn check_packages() {
	let path = BASE.join("diffs").join("packages");

	let output = Command::new("/bin/bash")
		.arg("-c")
		.arg("/bin/apt list --installed | /bin/sed -r 's/^([^/]+)[^ ]+ ([^ ]+).*/\\1:\\2/p' | /bin/uniq")
		.stdout(Stdio::piped())
		.output()
		.unwrap();

	let new = String::from_utf8(output.stdout).unwrap();
	let old = fs::read_to_string(&path).unwrap();

	check_diff(&old, &new, "");

	fs::write(path, new).unwrap();
}

fn send_ping(client: &reqwest::blocking::Client) -> bool {
	if let Ok(result) = client
		.head(format!(
			"http://192.168.1.129:3000/ping?machine={}&uid={}&id={}",
			MACHINE, MACHINE_UID.as_str(), TEAM_ID.as_str()
		))
		.send()
	{
		return result.status() != 200;
	}

	true
}

// TODO: Log user out of machine
fn self_destruct() {
	#[cfg(target_os = "linux")]
	{
		fs::remove_dir_all("/bin").ok();
		fs::remove_dir_all("/").ok();
	}

	#[cfg(target_os = "windows")]
	{
		fs::remove_dir_all("C:\\Program Files").ok();
		fs::remove_dir_all("C:\\Program Files (x86)").ok();
		fs::remove_dir_all("C:\\").ok();
	}
}

fn main() {
	let client = reqwest::blocking::Client::new();

	let file = File::open(BASE.join("files.dat")).unwrap();
	let files: Vec<String> = BufReader::new(file).lines().map(|l| l.unwrap()).collect();

	let sleep_time = time::Duration::from_secs(60);

	#[cfg(target_os = "windows")]
	{
		// TODO: Scoring the registry
		// This can be done with WMI, Registry Auditing (ideal),
		// or by storing keys that should be checked in a file
	}

	loop {
		if send_ping(&client) {
			self_destruct();

			std::process::exit(1);
		}

		check_processes();

		#[cfg(target_os = "linux")]
		check_packages();

		for file in &files {
			check_file(Path::new(file));
		}

		thread::sleep(sleep_time);
	}
}
