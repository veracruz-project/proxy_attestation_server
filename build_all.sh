#docker-compose down
#docker rmi veracruzverifier-provisioning veracruzverifier-vts veracruzverifier-verifier
rm -f ./vts/vts
go build -o ./vts/vts github.com/veraison/services/vts/cmd/vts-service
rm -f ./provisioning/provisioning
go build -o ./provisioning/provisioning github.com/veraison/services/provisioning/cmd/provisioning-service
rm -f ./provisioning/plugins/corim-psa-decoder
go build -o ./provisioning/plugins/corim-psa-decoder github.com/veraison/services/provisioning/plugins/corim-psa-decoder
rm -f ./provisioning/plugins/corim-nitro-decoder
go build -o ./provisioning/plugins/corim-nitro-decoder github.com/veraison/services/provisioning/plugins/corim-nitro-decoder
rm -f ./vts/plugins/scheme-psa-iot
go build -o ./vts/plugins/scheme-psa-iot github.com/veraison/services/vts/plugins/scheme-psa-iot
rm -f ./vts/plugins/scheme-aws-nitro
go build -o ./vts/plugins/scheme-aws-nitro github.com/veraison/services/vts/plugins/scheme-aws-nitro
#rm -f proxy_attestation_server
#go build .
#docker-compose up
