
function up(){

    docker-compose -f network/docker-compose.yaml up -d --build
    docker logs swipl-notebook -f
    
}

function pause(){
    docker-compose -f network/docker-compose.yaml pause
}

function unpause(){
    docker-compose -f network/docker-compose.yaml unpause
}
function down(){

    docker-compose -f network/docker-compose.yaml down --volumes --remove-orphans
    # docker image rm network_swipl-notebook
}

function restart(){
    down
    up
}

"$@"
