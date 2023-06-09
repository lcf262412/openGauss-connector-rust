use futures::{join, FutureExt};
use std::time::Duration;
use tokio::time;
use tokio_opengauss::error::SqlState;
use tokio_opengauss::{Client, NoTls};

async fn connect(s: &str) -> Client {
    let (client, connection) = tokio_opengauss::connect(s, NoTls).await.unwrap();
    let connection = connection.map(|e| e.unwrap());
    tokio::spawn(connection);

    client
}

async fn smoke_test(s: &str) {
    let client = connect(s).await;

    let stmt = client.prepare("SELECT $1::INT").await.unwrap();
    let rows = client.query(&stmt, &[&1i32]).await.unwrap();
    assert_eq!(rows[0].get::<_, i32>(0), 1i32);
}

#[tokio::test]
#[ignore] // FIXME doesn't work with our docker-based tests :(
async fn unix_socket() {
    smoke_test("host=/var/run/opengauss port=5433 user=postgres password=openGauss#2023").await;
}

#[tokio::test]
async fn tcp() {
    smoke_test("host=localhost port=5433 user=postgres password=openGauss#2023").await;
}

#[tokio::test]
async fn multiple_hosts_one_port() {
    smoke_test("host=foobar.invalid,localhost port=5433 user=postgres password=openGauss#2023").await;
}

#[tokio::test]
async fn multiple_hosts_multiple_ports() {
    smoke_test("host=foobar.invalid,localhost port=5432,5433 user=postgres password=openGauss#2023").await;
}

#[tokio::test]
async fn wrong_port_count() {
    tokio_opengauss::connect("host=localhost port=5433,5433 user=postgres password=openGauss#2023", NoTls)
        .await
        .err()
        .unwrap();
}

#[tokio::test]
async fn target_session_attrs_ok() {
    smoke_test("host=localhost port=5433 user=postgres password=openGauss#2023 target_session_attrs=read-write").await;
}

#[tokio::test]
async fn target_session_attrs_err() {
    tokio_opengauss::connect(
        "host=localhost port=5433 user=postgres password=openGauss#2023 target_session_attrs=read-write
         options='-c default_transaction_read_only=on'",
        NoTls,
    )
    .await
    .err()
    .unwrap();
}

#[tokio::test]
async fn cancel_query() {
    let client = connect("host=localhost port=5433 user=postgres password=openGauss#2023").await;

    let cancel_token = client.cancel_token();
    let cancel = cancel_token.cancel_query(NoTls);
    let cancel = time::sleep(Duration::from_millis(100)).then(|()| cancel);

    let sleep = client.batch_execute("SELECT pg_sleep(100)");

    match join!(sleep, cancel) {
        (Err(ref e), Ok(())) if e.code() == Some(&SqlState::QUERY_CANCELED) => {}
        t => panic!("unexpected return: {:?}", t),
    }
}
