use super::*;

#[test]
fn readiness_rejects_paused_conflicts_and_unknown_observations() {
    let healthy_observation = Observation {
        state: "available",
        conflicts: "none_observed",
        paused: Some(false),
        status: Some("watching"),
        conflict_count: Some(0),
    };
    assert!(healthy(&healthy_observation).is_ok());
    for observation in [
        Observation {
            paused: Some(true),
            ..healthy_observation.clone()
        },
        Observation {
            paused: None,
            ..healthy_observation.clone()
        },
        Observation {
            conflicts: "detected",
            conflict_count: Some(1),
            ..healthy_observation.clone()
        },
        Observation {
            conflicts: "unknown",
            ..healthy_observation.clone()
        },
        Observation {
            status: Some("scanning"),
            ..healthy_observation.clone()
        },
        Observation {
            conflict_count: None,
            ..healthy_observation.clone()
        },
        Observation {
            state: "unavailable",
            ..healthy_observation.clone()
        },
    ] {
        assert!(healthy(&observation).is_err());
    }
}
