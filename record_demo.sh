#!/bin/bash
# Script to record the demo using Asciinema and convert to SVG

echo "Starting Asciinema recording..."
echo "Running DemoApp in unsafe and safe modes..."

./venv/bin/asciinema rec --overwrite --command "bash -c 'echo \"$ ./gradlew :demo:run --args=\\\"unsafe\\\" -q\"; ./gradlew :demo:run --args=\"unsafe\" -q; echo \"\"; echo \"$ ./gradlew :demo:run --args=\\\"safe\\\" -q\"; ./gradlew :demo:run --args=\"safe\" -q; echo \"\"; echo \"$ exit\"'" demo.cast

echo "Recording finished. Converting to SVG..."
./node_modules/.bin/svg-term --in demo.cast --out presentation/demo.svg --window --no-cursor

echo "Done! The SVG is saved at presentation/demo.svg"