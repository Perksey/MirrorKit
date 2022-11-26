#!/usr/bin/env -S bash -eu

# dumb script to do a full test of mirrorkit on a repo

(
    trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT
    cd "$(dirname "${BASH_SOURCE}")"
    rm -rf fulltest
    mkdir -p fulltest/ingest
    mkdir -p fulltest/tx_work
    mkdir -p fulltest/rx_work
    HERE_DIR="$(readlink -f .)/fulltest"
    cd fulltest
    git init --bare tx_repo
    git init --bare rx_repo
    git clone "file://${HERE_DIR}/tx_repo" tx_repo2
    cd tx_repo2
    echo "Hello" >> README.txt
    git add .
    git commit -m "Initial commit"
    git push --set-upstream origin master
    EXPECTED_REV=$(git rev-parse HEAD)
    cd ../..
    cargo run -- add fulltest/tx.json "test" "file://${HERE_DIR}/tx_repo" "file://${HERE_DIR}/rx_repo"
    cargo run -- tx-server fulltest/tx.json fulltest/ingest fulltest/tx_work &
    TX_PID=$!
    cargo run -- rx-server fulltest/rx.json fulltest/ingest fulltest/rx_work &
    RX_PID=$!
    sleep 1
    cd fulltest/rx_repo
    ACTUAL_REV=$(git rev-parse refs/heads/master)
    if [ "${EXPECTED_REV}" = "${ACTUAL_REV}" ]; then
        echo -e "\e[32mFULL EXPORT TEST PASSED.\e[0m"
    else
        echo -e "\e[31mFULL EXPORT TEST FAILED.\e[0m"
        exit 1
    fi
    cd ../tx_repo2
    echo ", world!" >> README.txt
    git add .
    git commit -m "Add world!"
    git push --set-upstream origin master
    git push origin master:refs/tags/v1.0.0
    EXPECTED_REV=$(git rev-parse HEAD)
    cd ../..
    sleep 1
    cargo run -- tx fulltest/tx.json "test" master
    sleep 1
    cd fulltest/rx_repo
    ACTUAL_REV=$(git rev-parse refs/heads/master)
    if [ "${EXPECTED_REV}" = "${ACTUAL_REV}" ]; then
        echo -e "\e[32mDELTA EXPORT (BRANCH) TEST PASSED.\e[0m"
    else
        echo -e "\e[31mDELTA EXPORT (BRANCH) TEST FAILED.\e[0m"
        exit 1
    fi
    ACTUAL_REV=$(git rev-parse refs/tags/v1.0.0)
    if [ "${EXPECTED_REV}" = "${ACTUAL_REV}" ]; then
        echo -e "\e[32mDELTA EXPORT (TAG) TEST PASSED.\e[0m"
    else
        echo -e "\e[31mDELTA EXPORT (TAG) TEST FAILED.\e[0m"
        exit 1
    fi
)