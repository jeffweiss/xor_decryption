require 'set'
def list_to_int_array(numbers)
  numbers.split(',').map(&:to_i)
end

def string_to_int_array(text)
  text.chars.map(&:ord)
end

def int_array_to_list(array)
  array.map(&:to_s).join(',')
end

def int_array_to_string(array)
  array.map(&:chr).join
end

def process(int_array, key, valid, allowable_bad=15)
  ret_value = []
  invalid_count = 0
  int_array.each_with_index do |item, index|
    new_val = (item ^ key[index % key.size])
    invalid_count += 1 unless valid.include?(new_val)
    return [] if invalid_count > allowable_bad
    ret_value << new_val
  end
  ret_value
end

def valid_chars
  ret = []
  'a'.upto('z').map {|c| ret << c }
  'A'.upto('Z').map {|c| ret << c }
  '0'.upto('9').map {|c| ret << c }
  " !,.-()[]\"'\t\r\n".chars.map { |c| ret << c }
  ret
end

def valid?(plaintext, all_words, ratio = 0.75)
  sample_size = 10
  test_words = plaintext.downcase.gsub(/[^a-z]/, ' ').split.select{|w| w.length > 4}.sample(sample_size)
  matched_word_count = test_words.map { |w| all_words.include?(w) ? 1 : 0 }.inject(0) {|n, i| n + i}
  (matched_word_count / test_words.size.to_f) >= ratio 
end

def keyspace
  'aaaa'.upto('zzzz').map(&:to_s)
end
ciphertext = File.read('../ciphertext')
all_words = File.read('/usr/share/dict/words').split.select{|w| w.length > 4}.to_set
ints = list_to_int_array(ciphertext)

ks = keyspace
puts "number of possible keys: #{ks.size}"
puts "valid chars: #{valid_chars.join}"
start = Time.now
all_possibilities = Hash.new
valid = string_to_int_array(valid_chars.join).to_set
ks.each_with_index do |word, i| 
  if i%1000 == 0
    now = Time.now
    elapsed_seconds = [(now - start).to_f, 1].max
    keys_per_second = [i.to_f / elapsed_seconds, 1].max
    eta = ((ks.size - i) / keys_per_second).to_i
    print "\t%s -- %.02f keys/s -- ETA %s seconds     \r" % [word, keys_per_second, eta]
  end
  k = string_to_int_array(word)
  plaintext = int_array_to_string(process(ints, k, valid))
  all_possibilities[word] = plaintext if valid?(plaintext, all_words)
end
puts
all_possibilities.each_pair do |key, plaintext|
  puts "CIPHER KEY: #{key}"
  puts "PLAIN TEXT:"
  puts plaintext
end
