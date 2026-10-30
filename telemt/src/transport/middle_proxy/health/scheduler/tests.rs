use super::*;
use crate::transport::middle_proxy::pool_writer_security_tests::make_pool;

#[tokio::test]
async fn deferred_and_stale_completions_preserve_round_budget_and_deadlines() {
    let pool = make_pool().await;
    let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
        .await;
    let observation = Arc::new(check_family(IpFamily::V4, &pool).await);
    let mut scheduler = HealthScheduler::default();
    scheduler.observe(&HashMap::from([(IpFamily::V4, observation.clone())]));
    let key = (2, IpFamily::V4);
    let entry = observation.floor.by_dc[&2].clone();
    let job = HealthJob {
        key,
        kind: JobKind::Transfer,
        observation,
        entry,
        round: 4,
    };
    let due = Instant::now() - Duration::from_secs(1);
    let state = scheduler.groups.get_mut(&key).unwrap();
    state.round = 4;
    state.round_left = 3;
    state.round_active = true;
    state.due = Some(due);
    scheduler.completed(&pool, job.clone(), JobOutcome::Deferred);
    let state = &scheduler.groups[&key];
    assert!(state.deferred);
    assert_eq!(state.round_left, 3);
    assert_eq!(state.due, Some(due));
    let state = scheduler.groups.get_mut(&key).unwrap();
    state.deferred = false;
    state.round_active = false;
    scheduler.completed(&pool, job.clone(), JobOutcome::Completed(None));
    scheduler.completed(&pool, job, JobOutcome::Deferred);
    let state = &scheduler.groups[&key];
    assert!(!state.deferred);
    assert_eq!(state.round_left, 3);
    assert_eq!(state.due, Some(due));
}

#[tokio::test]
async fn queue_survives_repeated_observations_without_starving_later_groups() {
    let pool = make_pool().await;
    pool.update_proxy_maps(
        (1..=12)
            .map(|dc| (dc, vec![("127.0.0.1".parse().unwrap(), 443)]))
            .collect(),
        None,
    )
    .await;
    let observation = Arc::new(check_family(IpFamily::V4, &pool).await);
    let observations = HashMap::from([(IpFamily::V4, observation)]);
    let mut scheduler = HealthScheduler::default();
    scheduler.observe(&observations);
    let expected = scheduler.queue.iter().copied().collect::<HashSet<_>>();
    let mut visited = HashSet::new();
    for _ in 0..expected.len() {
        let key = scheduler.queue.pop_front().unwrap();
        scheduler.queue.push_back(key);
        visited.insert(key);
        scheduler.observe(&observations);
    }
    assert_eq!(visited, expected);
}
