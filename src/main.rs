use std::{
	fs::{self, File},
	io::{BufRead, BufReader},
	path::Path,
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

fn submit_answer(answer: &str, removed: bool, path: &Path, team_id: &str) {
	Command::new(path)
		.arg(answer)
		.arg(if removed { "1" } else { "0" })
		.env("TEAM_ID", team_id)
		.spawn()
		.ok();
}

fn format_answer(answer: &str, replacer: &Regex) -> String {
	let replaced = replacer.replace_all(answer.trim(), "=");
	let lower = replaced.to_lowercase();
	let mut data = lower.split_whitespace().into_iter().collect::<Vec<&str>>();

	data.sort();

	data.join(" ")
}

fn check_file(path: &Path, bin: &Path, base: &Path, replacer: &Regex, team_id: &str) {
	let path_str = path.to_str().unwrap();
	let mut hasher = Sha512::new();

	hasher.update(path_str);

	let hash = hex::encode(hasher.finalize_reset());
	let stored_path = base.join("diffs").join(hash.as_str());

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

	check_diff(&old, &new, path_str, bin, replacer, team_id);

	if !new_exists {
		fs::remove_file(stored_path).ok();

		if stored_exists {
			submit_answer(path_str, true, bin, team_id);
		}
	} else {
		fs::write(stored_path, new).unwrap();

		if !stored_exists {
			submit_answer(path_str, false, bin, team_id);
		}
	}
}

fn check_diff(old: &String, new: &String, path_str: &str, bin: &Path, replacer: &Regex, team_id: &str) {
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

		#[cfg(target_os = "linux")]
		if path_str == "/etc/passwd" {
			if let Some(username) = line.split(':').next() {
				submit_answer(&format!("{}{}", username, path_str), removed, bin);
			}
		} else if path_str == "/etc/group" {
			let mut split = line.split(':');

			if let Some(group) = split.next() {
				if let Some(users) = split.nth(2) {
					for user in users.split(',') {
						submit_answer(&format!("{}:{}{}", group, user, path_str), removed, bin);
					}
				}
			}
		}

		submit_answer(
			&format!("{}{}", format_answer(line, &replacer), path_str),
			removed,
			bin,
			team_id
		);
	}
}

fn check_processes(base: &Path, bin: &Path, replacer: &Regex, team_id: &str) {
	let path = base.join("diffs").join("processes");

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

	check_diff(&old, &new, "", bin, replacer, team_id);

	fs::write(path, new).unwrap();
}

#[cfg(target_os = "linux")]
fn check_packages(base: &Path, bin: &Path, replacer: &Regex, team_id: &str) {
	let path = base.join("diffs").join("packages");

	let output = Command::new("/bin/bash")
		.arg("-c")
		.arg("/bin/apt list --installed | /bin/sed -r 's/^([^/]+)[^ ]+ ([^ ]+).*/\\1:\\2/p' | /bin/uniq")
		.stdout(Stdio::piped())
		.output()
		.unwrap();

	let new = String::from_utf8(output.stdout).unwrap();
	let old = fs::read_to_string(&path).unwrap();

	check_diff(&old, &new, "", bin, replacer, team_id);

	fs::write(path, new).unwrap();
}

fn send_ping(machine_uid: &str, team_id: &str, client: &reqwest::blocking::Client) -> bool {
	if let Ok(result) = client
		.head(format!(
			"http://192.168.1.129:3000/ping?machine={}&uid={}&id={}",
			MACHINE, machine_uid, team_id
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
	#[cfg(target_os = "windows")]
	let base = Path::new("C:\\CyberPatriot");

	#[cfg(target_os = "windows")]
	let bin = base.join("CCSCheck.exe");

	#[cfg(target_os = "linux")]
	let base = Path::new("/opt/CyberPatriot");

	#[cfg(target_os = "linux")]
	let bin = base.join("CCSCheck");

	let machine_uid = machine_uid::get().unwrap();
	let client = reqwest::blocking::Client::new();
	let team_id = std::env::var("TEAM_ID").unwrap_or("0123-0123-0123".to_string());

	let replacer = Regex::new("\\s*=\\s*").unwrap();

	let file = File::open(base.join("files.dat")).unwrap();
	let files: Vec<String> = BufReader::new(file).lines().map(|l| l.unwrap()).collect();

	let sleep_time = time::Duration::from_secs(60);

	#[cfg(target_os = "windows")]
	{
		// TODO: Scoring the registry
		// This can be done with WMI, Registry Auditing (ideal),
		// or by storing keys that should be checked in a file
	}

	loop {
		if send_ping(&machine_uid, &team_id, &client) {
			self_destruct();

			std::process::exit(1);
		}

		check_processes(base, &bin, &replacer, &team_id);

		#[cfg(target_os = "linux")]
		check_packages(base, &bin, &replacer, &team_id);

		for file in &files {
			check_file(Path::new(file), &bin, base, &replacer, &team_id);
		}

		thread::sleep(sleep_time);
	}
}
