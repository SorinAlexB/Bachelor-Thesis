# Start tart VMs
tart run linux-sandbox --no-graphics &
echo "Started linux-sandbox VM on IP $(tart ip linux-sandbox)"
tart run macos-sandbox --no-graphics &
echo "Started linux-sandbox VM on IP $(tart ip macos-sandbox)"