import pytest

from smcp_gateway.bench.world import World


@pytest.fixture(scope="session")
def world(tmp_path_factory):
    return World(tmp_path_factory.mktemp("world"))
