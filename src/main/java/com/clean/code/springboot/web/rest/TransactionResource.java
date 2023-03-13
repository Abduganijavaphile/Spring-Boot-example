package com.clean.code.springboot.web.rest;

import com.clean.code.springboot.model.Transaction;
import com.clean.code.springboot.service.TransactionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class TransactionResource {
    private final TransactionService transactionService;

    public TransactionResource(TransactionService transactionService) {
        this.transactionService = transactionService;
    }
    @GetMapping("/transactions")
    public ResponseEntity grtMsg(){
        return ResponseEntity.ok(transactionService.getAll());
    }

    @PostMapping("/transactions")
    public ResponseEntity create(@RequestBody Transaction transaction){
        return ResponseEntity.ok(transactionService.saveExch(transaction));
    }
    @PutMapping("/transactions")
    public ResponseEntity update(@RequestBody Transaction transaction){
        return ResponseEntity.ok(transactionService.update(transaction));
    }
}
