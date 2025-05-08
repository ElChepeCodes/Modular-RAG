import { useState, useEffect } from "react";
import axios from "axios";
import { Box, Button, Input, Textarea, VStack, HStack, Spinner } from "@chakra-ui/react";

interface AgentConfig {
    name: string;
    description: string;
    parameters: Record<string, string>;
  }
  
  const AgentInterface = () => {
    const [agents, setAgents] = useState<AgentConfig[]>([]);
    const [selectedAgent, setSelectedAgent] = useState<string>('');
  
    useEffect(() => {
      const loadAgents = async () => {
        const response = await axios.get('/api/agents');
        setAgents(response.data);
      };
      loadAgents();
    }, []);
  
    return (
      <div className="agent-container">
        <select 
          value={selectedAgent}
          onChange={(e) => setSelectedAgent(e.target.value)}
        >
          {agents.map(agent => (
            <option key={agent.name} value={agent.name}>
              {agent.name} - {agent.description}
            </option>
          ))}
        </select>
        
        {selectedAgent && (
          <div className="agent-parameters">
            {Object.entries(agents.find(a => a.name === selectedAgent)?.parameters || {}).map(
              ([param, desc]) => (
                <div key={param} className="param-field">
                  <label>{desc}</label>
                  <input 
                    type="text"
                    placeholder={param}
                    onChange={(e) => handleParamChange(param, e.target.value)}
                  />
                </div>
              )
            )}
          </div>
        )}
      </div>
    );
  };