//! Internet scheduler policy for the UDP-LI reference profile.

use conet_core::{ByteRate, MonoNs};

/// Queue/service classes. ACK and NACK remain inside `Feedback`; their kind is
/// never interpreted by the link scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendClass {
    Association,
    LinkControl,
    Feedback,
    FileData,
}

impl SendClass {
    pub const fn is_non_file(self) -> bool {
        !matches!(self, Self::FileData)
    }
}

/// Proposed reference defaults. The numeric policy is local to this profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerConfig {
    pub max_consecutive_non_file: u8,
    pub control_window: MonoNs,
    pub control_window_msgs: usize,
    pub control_window_bytes: usize,
    /// Maximum control bytes as a percentage of link-rate bytes in the window.
    pub control_window_fraction_percent: u8,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_consecutive_non_file: 2,
            control_window: MonoNs::new(100_000_000),
            control_window_msgs: 32,
            control_window_bytes: 32 * 1024,
            control_window_fraction_percent: 10,
        }
    }
}

/// Sliding profile-local budget for other link-control.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ControlWindow {
    start: Option<MonoNs>,
    msgs: usize,
    bytes: usize,
}

impl ControlWindow {
    pub fn can_send(
        &mut self,
        now: MonoNs,
        bytes: usize,
        target_rate: ByteRate,
        config: SchedulerConfig,
    ) -> bool {
        self.refresh(now, config);
        self.would_send(bytes, target_rate, config)
    }

    /// Check the window at `now` without mutating its refresh state.
    pub fn can_send_now(
        &self,
        now: MonoNs,
        bytes: usize,
        target_rate: ByteRate,
        config: SchedulerConfig,
    ) -> bool {
        let mut refreshed = *self;
        refreshed.refresh(now, config);
        refreshed.would_send(bytes, target_rate, config)
    }

    fn would_send(&self, bytes: usize, target_rate: ByteRate, config: SchedulerConfig) -> bool {
        let window_ns = config.control_window.as_nanos().max(0) as u128;
        let window_bytes = u128::from(target_rate).saturating_mul(window_ns) / 1_000_000_000;
        let fraction = u128::from(config.control_window_fraction_percent.min(100));
        let rate_cap_u128 = window_bytes.saturating_mul(fraction) / 100;
        let rate_cap = usize::try_from(rate_cap_u128).unwrap_or(usize::MAX);
        let byte_cap = config.control_window_bytes.min(rate_cap);
        self.msgs < config.control_window_msgs && self.bytes.saturating_add(bytes) <= byte_cap
    }

    pub fn record(&mut self, now: MonoNs, bytes: usize, config: SchedulerConfig) {
        self.refresh(now, config);
        if self.start.is_none() {
            self.start = Some(now);
        }
        self.msgs = self.msgs.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
    }

    pub const fn msgs(&self) -> usize {
        self.msgs
    }

    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    fn refresh(&mut self, now: MonoNs, config: SchedulerConfig) {
        if self
            .start
            .is_some_and(|start| now >= start.saturating_add(config.control_window))
        {
            *self = Self::default();
        }
    }
}

/// Choose a class after anti-starvation has been considered. The endpoint
/// supplies readiness and piggyback preference; this helper encodes the fixed
/// priority order.
pub fn choose_class(
    association_waiting: bool,
    link_control_waiting: bool,
    feedback_waiting: bool,
    file_data_waiting: bool,
    consecutive_non_file: u8,
    max_consecutive_non_file: u8,
) -> Option<SendClass> {
    if file_data_waiting && consecutive_non_file >= max_consecutive_non_file {
        return Some(SendClass::FileData);
    }
    if association_waiting {
        Some(SendClass::Association)
    } else if link_control_waiting {
        Some(SendClass::LinkControl)
    } else if feedback_waiting {
        Some(SendClass::Feedback)
    } else if file_data_waiting {
        Some(SendClass::FileData)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_cap_uses_ten_percent_of_bytes_in_the_window() {
        let config = SchedulerConfig::default();
        let mut window = ControlWindow::default();
        assert!(window.can_send(MonoNs::ZERO, 100, 10_000, config));
        window.record(MonoNs::ZERO, 100, config);
        assert!(!window.can_send(MonoNs::ZERO, 1, 10_000, config));
        assert!(window.can_send(MonoNs::new(100_000_000), 100, 10_000, config));
    }

    #[test]
    fn control_cap_scales_with_non_default_window() {
        let config = SchedulerConfig {
            control_window: MonoNs::new(200_000_000),
            ..SchedulerConfig::default()
        };
        let mut window = ControlWindow::default();
        assert!(window.can_send(MonoNs::ZERO, 200, 10_000, config));
        window.record(MonoNs::ZERO, 200, config);
        assert!(!window.can_send(MonoNs::ZERO, 1, 10_000, config));
        assert!(window.can_send(MonoNs::new(200_000_000), 200, 10_000, config));
    }

    #[test]
    fn anti_starvation_releases_file_data_after_two_non_file_sends() {
        assert_eq!(
            choose_class(false, true, true, true, 0, 2),
            Some(SendClass::LinkControl)
        );
        assert_eq!(
            choose_class(false, false, true, true, 2, 2),
            Some(SendClass::FileData)
        );
    }
}
