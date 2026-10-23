//! `Msvm_ConcreteJob` polling: the difference between "job started"
//! and "job succeeded".
//!
//! Hyper-V WMI methods return `4096` to mean *an asynchronous job has
//! been created*. Completion is `JobState == 7`; `8`, `9`, and `10`
//! are failure. Completed jobs are removed after ~5 minutes, so a poll
//! that finds no job checks the operation's actual effect rather than
//! reporting failure.

use std::time::{Duration, Instant};

use hvlab_core::error::{ErrorCode, HvError, Result};
use wmi::WMIConnection;

/// Terminal `JobState` for success.
pub const JOB_STATE_COMPLETED: u16 = 7;
/// Terminal `JobState` values for failure (terminated / killed / exception).
pub const JOB_STATE_FAILED: [u16; 3] = [8, 9, 10];

/// How a WMI job ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobOutcome {
    /// `JobState == 7`.
    Completed,
    /// `JobState` in 8..10, with the error code and description.
    Failed(u32, String),
    /// The job instance is gone. Callers must verify the operation's
    /// actual effect instead of assuming failure — jobs are retained
    /// only about five minutes after completion.
    Vanished,
}

/// What one poll saw.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Poll {
    /// The job exists and has not finished.
    Running,
    /// The job reached a terminal state.
    Terminal(JobOutcome),
    /// The job instance cannot be found.
    Gone,
}

/// Poll `job_path` until it reaches a terminal state or `deadline`.
///
/// A job that is *missing* and a job that is *running* are different
/// observations: only the former may be read as [`JobOutcome::Vanished`].
/// Because a poll can race job creation, a missing job is re-checked for
/// a short grace period before being believed.
///
/// # Errors
///
/// `ErrorCode::Timeout` when the deadline passes first.
pub fn await_wmi_job(
    conn: &WMIConnection,
    job_path: &str,
    deadline: Instant,
) -> Result<JobOutcome> {
    if job_path.is_empty() {
        return Ok(JobOutcome::Vanished);
    }
    let mut gone_since: Option<Instant> = None;
    loop {
        match poll_once(conn, job_path) {
            Poll::Terminal(outcome) => return Ok(outcome),
            Poll::Running => gone_since = None,
            Poll::Gone => {
                // Jobs are removed ~5 minutes after completion, so a
                // missing job usually means "already finished and
                // reaped". Require the absence to persist before
                // trusting it, so a poll racing creation is not
                // mistaken for a vanished job.
                let since = *gone_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= VANISH_GRACE {
                    return Ok(JobOutcome::Vanished);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(HvError::new(
                ErrorCode::Timeout,
                format!("job at {job_path} did not reach a terminal state before the deadline"),
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// How long a missing job must stay missing before it is called vanished.
const VANISH_GRACE: Duration = Duration::from_secs(1);

/// Poll cadence while a job runs.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// One poll of a job's state.
fn poll_once(conn: &WMIConnection, job_path: &str) -> Poll {
    #[derive(serde::Deserialize)]
    #[serde(rename = "Msvm_ConcreteJob")]
    struct StateOnly {
        #[serde(rename = "JobState")]
        job_state: u16,
        #[serde(rename = "ErrorCode", default)]
        error_code: Option<u32>,
        #[serde(rename = "ErrorDescription", default)]
        error_description: Option<String>,
    }
    // `job_path` arrives as a full object path from the method call
    // (e.g. `\\\.\root\virtualization\v2:Msvm_ConcreteJob.InstanceID="x"`).
    // WQL needs `FROM <class> WHERE <key>`, so parse the class and key
    // filter out of the path. A malformed path or a query error means
    // the job is gone — completed jobs are removed after ~5 minutes.
    let rel = job_path.rsplit(':').next().unwrap_or(job_path);
    let (class, key_filter) = rel.split_once('.').unwrap_or((rel, ""));
    let query = if key_filter.is_empty() {
        format!("SELECT JobState, ErrorCode, ErrorDescription FROM {class}")
    } else {
        format!("SELECT JobState, ErrorCode, ErrorDescription FROM {class} WHERE {key_filter}")
    };
    let rows: Vec<StateOnly> = match conn.raw_query(&query) {
        Ok(rows) => rows,
        Err(_) => return Poll::Gone, // query error == job unqueryable
    };
    let Some(job) = rows.first() else {
        return Poll::Gone;
    };
    match job.job_state {
        JOB_STATE_COMPLETED => Poll::Terminal(JobOutcome::Completed),
        s if JOB_STATE_FAILED.contains(&s) => Poll::Terminal(JobOutcome::Failed(
            job.error_code.unwrap_or(0),
            job.error_description.clone().unwrap_or_default(),
        )),
        _ => Poll::Running,
    }
}

/// Percent complete from a live job, for progress reporting.
///
/// # Errors
///
/// `ErrorCode::Transport` on WMI failure.
pub fn job_percent(conn: &WMIConnection, job_path: &str) -> Result<Option<u16>> {
    #[derive(serde::Deserialize)]
    #[serde(rename = "Msvm_ConcreteJob")]
    struct Pct {
        #[serde(rename = "PercentComplete", default)]
        percent_complete: Option<u16>,
    }
    let query = format!("SELECT PercentComplete FROM {job_path}");
    let rows: Vec<Pct> = conn
        .raw_query(&query)
        .map_err(|e| HvError::new(ErrorCode::Transport, format!("job poll failed: {e}")))?;
    Ok(rows.first().and_then(|j| j.percent_complete))
}

/// Errors specific to job interpretation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WmiJobError {
    /// The job path WMI returned was empty.
    #[error("job path was empty; the operation may not have started")]
    EmptyJobPath,
}

#[cfg(test)]
mod tests {
    use super::*;

    mod outcomes {
        use super::*;

        #[test]
        fn completed_is_seven() {
            assert_eq!(JOB_STATE_COMPLETED, 7);
        }

        #[test]
        fn failure_states_are_eight_nine_ten() {
            assert_eq!(JOB_STATE_FAILED, [8, 9, 10]);
        }
    }
}

#[cfg(test)]
mod probe {
    use wmi::WMIConnection;

    #[derive(serde::Deserialize)]
    #[serde(rename = "Msvm_ConcreteJob")]
    struct JobRow {}

    /// Throwaway diagnostic kept as a regression test: a missing job key
    /// yields zero rows, which `await_wmi_job` must treat as Vanished.
    #[test]
    fn probe_missing_job_query() {
        let conn = WMIConnection::with_namespace_path(r"ROOT\virtualization\v2").expect("connect");
        let rows: Vec<JobRow> = conn
            .raw_query("SELECT JobState FROM Msvm_ConcreteJob WHERE InstanceID='missing-job-id'")
            .expect("query runs");
        assert!(rows.is_empty(), "missing job should return no rows");
    }
}
