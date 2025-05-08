// frontend/src/App.tsx
import { useState } from 'react';
import { Box, Button, Input, Textarea, VStack, HStack, Spinner } from '@chakra-ui/react';
import axios from 'axios';

function App() {
  const [file, setFile] = useState<File | null>(null);
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState('');
  const [loading, setLoading] = useState(false);
  const [processing, setProcessing] = useState(false);

  const handleUpload = async () => {
    if (!file) return;
    
    setProcessing(true);
    const formData = new FormData();
    formData.append('file', file);
    
    try {
      await axios.post('http://localhost:8000/upload', formData, {
        headers: {'Content-Type': 'multipart/form-data'}
      });
    } catch (error) {
      console.error('Upload failed:', error);
    }
    setProcessing(false);
  };

  const handleQuery = async () => {
    if (!question) return;
    
    setLoading(true);
    try {
      const response = await axios.post('http://localhost:8000/query', {
        question,
        llm_type: 'ollama',
        model: 'llama2'
      });
      setAnswer(response.data.answer);
    } catch (error) {
      console.error('Query failed:', error);
      setAnswer('Error getting response');
    }
    setLoading(false);
  };

  return (
    <Box p={8} maxW="800px" mx="auto">
      <VStack gap={6} align="stretch">
        <HStack>
          <Input 
            type="file" 
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            accept=".txt"
          />
          <Button 
                      onClick={handleUpload}
                      colorScheme="blue"
                      loading={processing}
                    >
                      {processing ? <Spinner size="sm" /> : 'Upload Document'}
                    </Button>
        </HStack>

        <Textarea
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="Ask your question..."
          minH="100px"
        />
        
        <Button 
                  onClick={handleQuery}
                  colorScheme="green"
                  loading={loading}
                >
                  {loading ? <Spinner size="sm" /> : 'Ask'}
                </Button>

        {answer && (
          <Box p={4} borderWidth={1} borderRadius="md">
            <strong>Answer:</strong>
            <Box mt={2}>{answer}</Box>
          </Box>
        )}
      </VStack>
    </Box>
  );
}

export default App;