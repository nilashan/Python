sentence = 'It is raining cats and dogs'
words = sentence.split()
print words
lengths = map(lambda word: len(word), words)
print lengths
