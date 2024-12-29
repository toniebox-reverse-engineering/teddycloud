certs_path="/teddycloud/certs"
echo "-----------------------------------"
echo "Checking teddyCloud certificates..."
echo "-----------------------------------"

# check server certificates
files=( "ca.der" "ca-key.pem" "ca-root.pem" "ca-root.srl" "teddy-cert.pem" "teddy-key.csr" "teddy-key.pem" )
echo -e "\nServer:"
echo "-------"
for file in "${files[@]}"
do
  filename=$(echo -en "$file: ")
  status=$([ -f "$certs_path/server/$file" ] && echo -e "\e[32mOK\e[0m" || echo -e "\e[31mFile not found!\e[0m")
  # TeddyCloud CA validation
  if [[ $file == "ca.der" ]]; then
    if [ -f "$certs_path/$file" ] && [ $(cat "$certs_path/$file" | grep -c "Teddy.* CA") -eq 0 ]; then
      status=$(echo -e "\e[31mWrong server CA, not from Teddycloud!\e[0m")
    fi
  fi
  printf "%-26s %-10s\n" "$filename" "$status"
done

# check default client certificates
files=( "ca.der" "client.der" "private.der" )
echo -e "\nClient (default):"
echo "-----------------"
for file in "${files[@]}"
do
  filename=$(echo -en "$file: ")
  status=$([ -f "$certs_path/client/$file" ] && echo -e "\e[32mOK\e[0m" || echo -e "\e[31mFile not found!\e[0m")
  # Boxine CA validation
  if [[ $file == "ca.der" ]]; then
    if [ -f "$certs_path/client/$file" ] && [ $(cat "$certs_path/client/$file" | grep -c "Boxine CA") -eq 0 ]; then
      status=$(echo -e "\e[31mWrong client CA, not from Boxine!\e[0m")
    fi
  fi
  printf "%-26s %-10s\n" "$filename" "$status"
done

# check client certificates for each box id
echo -e "\nClient per box:"
echo "---------------"
for dir in $certs_path/client/*/ 
do
    box_path=${dir%*/} 
    box_id=${box_path##*/}  
    for file in "${files[@]}" 
    do
      filename=$(echo -en "$box_id/$file: ")
      status=$([ -f "$box_path/$file" ] && echo -e "\e[32mOK\e[0m" || echo -e "\e[31mFile not found!\e[0m")
      # Boxine CA validation
      if [[ $file == "ca.der" ]]; then
        if [ -f "$box_path/$file" ] && [ $(cat "$box_path/$file" | grep -c "Boxine CA") -eq 0 ]; then
                status=$(echo -e "\e[31mWrong client CA, not from Boxine!\e[0m")
              fi
      fi
      printf "%-26s %-10s\n" "$filename" "$status"
    done
done
