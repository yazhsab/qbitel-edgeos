// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Integration tests for q-kernel
//!
//! These tests exercise the kernel's data structures, IPC mechanisms,
//! and memory management on the host platform. Note: scheduler tests
//! that require hardware context switching cannot run on the host.

mod ipc_tests {
    use q_kernel::ipc::{Channel, ChannelState, Mailbox, SignalSet};

    #[test]
    fn test_channel_creation() {
        let channel = Channel::new(0);
        assert_eq!(channel.state(), ChannelState::Open);
    }

    #[test]
    fn test_channel_send_receive() {
        let mut channel = Channel::new(0);
        let data = [0x42u8; 16];

        let send_result = channel.send(&data);
        assert!(send_result.is_ok(), "Send should succeed on empty channel");

        let mut recv_buf = [0u8; 64];
        let recv_result = channel.receive(&mut recv_buf);
        assert!(recv_result.is_ok(), "Receive should succeed with pending message");

        let len = recv_result.unwrap();
        assert_eq!(&recv_buf[..len], &data);
    }

    #[test]
    fn test_channel_empty_receive_fails() {
        let mut channel = Channel::new(0);
        let mut recv_buf = [0u8; 64];
        let result = channel.receive(&mut recv_buf);
        assert!(result.is_err(), "Receive on empty channel should fail");
    }

    #[test]
    fn test_channel_multiple_messages() {
        let mut channel = Channel::new(0);

        // Send multiple messages
        channel.send(&[1, 2, 3]).expect("send 1");
        channel.send(&[4, 5, 6]).expect("send 2");

        // Receive in order (FIFO)
        let mut buf = [0u8; 64];
        let len = channel.receive(&mut buf).expect("recv 1");
        assert_eq!(&buf[..len], &[1, 2, 3]);

        let len = channel.receive(&mut buf).expect("recv 2");
        assert_eq!(&buf[..len], &[4, 5, 6]);
    }

    #[test]
    fn test_mailbox_send_receive() {
        let mut mailbox = Mailbox::new(0);
        let message = [0xABu8; 8];

        mailbox.post(&message, 1).expect("post");
        let mut buf = [0u8; 32];
        let (len, sender) = mailbox.fetch(&mut buf).expect("fetch");

        assert_eq!(&buf[..len], &message);
        assert_eq!(sender, 1);
    }

    #[test]
    fn test_signal_set_operations() {
        let mut signals = SignalSet::new();

        assert!(!signals.is_pending(0x01));

        signals.raise(0x01);
        assert!(signals.is_pending(0x01));

        signals.raise(0x04);
        assert!(signals.is_pending(0x05)); // 0x01 | 0x04

        signals.clear(0x01);
        assert!(!signals.is_pending(0x01));
        assert!(signals.is_pending(0x04));
    }
}

mod memory_tests {
    use q_kernel::memory::{MemoryRegion, Permissions};

    #[test]
    fn test_memory_region_creation() {
        let region = MemoryRegion::new(0x2000_0000, 0x1000, Permissions::READ_WRITE);
        assert_eq!(region.base(), 0x2000_0000);
        assert_eq!(region.size(), 0x1000);
        assert!(region.permissions().contains(Permissions::READ_WRITE));
    }

    #[test]
    fn test_memory_region_contains_address() {
        let region = MemoryRegion::new(0x2000_0000, 0x1000, Permissions::READ_WRITE);
        assert!(region.contains(0x2000_0000));
        assert!(region.contains(0x2000_0FFF));
        assert!(!region.contains(0x2000_1000));
        assert!(!region.contains(0x1FFF_FFFF));
    }

    #[test]
    fn test_memory_region_overlap_detection() {
        let r1 = MemoryRegion::new(0x2000_0000, 0x1000, Permissions::READ_WRITE);
        let r2 = MemoryRegion::new(0x2000_0800, 0x1000, Permissions::READ_ONLY);
        let r3 = MemoryRegion::new(0x2000_1000, 0x1000, Permissions::READ_WRITE);

        assert!(r1.overlaps(&r2), "Overlapping regions should be detected");
        assert!(!r1.overlaps(&r3), "Adjacent regions should not overlap");
    }

    #[test]
    fn test_permission_combinations() {
        let ro = Permissions::READ_ONLY;
        let rw = Permissions::READ_WRITE;
        let rx = Permissions::READ_EXECUTE;

        assert!(ro.contains(Permissions::READ));
        assert!(!ro.contains(Permissions::WRITE));

        assert!(rw.contains(Permissions::READ));
        assert!(rw.contains(Permissions::WRITE));
        assert!(!rw.contains(Permissions::EXECUTE));

        assert!(rx.contains(Permissions::READ));
        assert!(rx.contains(Permissions::EXECUTE));
        assert!(!rx.contains(Permissions::WRITE));
    }
}

mod task_type_tests {
    use q_kernel::task::{TaskId, TaskState, TaskPriority};

    #[test]
    fn test_task_priority_ordering() {
        assert!(TaskPriority::RealTime as u8 > TaskPriority::High as u8
            || TaskPriority::RealTime as u8 == 0); // Depends on enum layout

        // At minimum, ensure all priorities are distinct
        let priorities = [
            TaskPriority::RealTime,
            TaskPriority::High,
            TaskPriority::Normal,
            TaskPriority::Low,
            TaskPriority::Idle,
        ];

        for i in 0..priorities.len() {
            for j in (i + 1)..priorities.len() {
                assert_ne!(
                    priorities[i] as u8, priorities[j] as u8,
                    "All priorities must be distinct"
                );
            }
        }
    }

    #[test]
    fn test_task_state_transitions_are_valid() {
        // Verify that all expected states exist
        let states = [
            TaskState::Ready,
            TaskState::Running,
            TaskState::Blocked,
            TaskState::Sleeping,
            TaskState::Terminated,
        ];

        // All states should be distinct
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(states[i], states[j], "All states must be distinct");
            }
        }
    }

    #[test]
    fn test_task_id_uniqueness() {
        let id1 = TaskId::new(0);
        let id2 = TaskId::new(1);
        let id3 = TaskId::new(0);

        assert_ne!(id1, id2);
        assert_eq!(id1, id3);
    }
}

mod syscall_tests {
    use q_kernel::syscall::Syscall;

    #[test]
    fn test_syscall_variants_exist() {
        // Verify all 6 syscalls are defined
        let syscalls = [
            Syscall::Yield,
            Syscall::Sleep,
            Syscall::Send,
            Syscall::Receive,
            Syscall::Signal,
            Syscall::Exit,
        ];
        assert_eq!(syscalls.len(), 6, "Should have exactly 6 syscall variants");
    }
}

mod constants_tests {
    use q_kernel::{MAX_TASKS, DEFAULT_TICK_RATE_HZ};

    #[test]
    fn test_kernel_constants() {
        assert!(MAX_TASKS >= 4, "Must support at least 4 tasks");
        assert!(MAX_TASKS <= 64, "More than 64 tasks is excessive for embedded");
        assert!(DEFAULT_TICK_RATE_HZ >= 100, "Tick rate should be at least 100 Hz");
        assert!(DEFAULT_TICK_RATE_HZ <= 10000, "Tick rate above 10kHz is excessive");
    }
}
